use purgo_domain::{DisarmOutput, DomainError, FileFormat, Policy, Sandbox};
use purgo_filters::wire::{decode_result, DecodedResult, FLAG_STRIP_METADATA, FORMAT_PNG};
use wasmtime::{
    Config, Engine, Instance, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder,
    TypedFunc,
};

use crate::disarm::png::{png_malformed, png_removed_item};

const FUEL_BUDGET: u64 = 10_000_000_000;

const MAX_GUEST_MEMORY: usize = 512 * 1024 * 1024;

const RESULT_LEN_SLACK: usize = 64 * 1024;

fn result_len_cap(input_len: usize) -> usize {
    input_len.saturating_mul(2).saturating_add(RESULT_LEN_SLACK)
}

pub struct WasmtimeSandbox {
    engine: Engine,
    module: Module,
}

type HostState = StoreLimits;

fn sandbox_failure(reason: impl Into<String>) -> DomainError {
    DomainError::SandboxFailure(reason.into())
}

impl WasmtimeSandbox {
    pub fn new(wasm_bytes: &[u8]) -> Result<Self, DomainError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)
            .map_err(|e| sandbox_failure(format!("cannot configure wasm engine: {e}")))?;
        let module = Module::new(&engine, wasm_bytes)
            .map_err(|e| sandbox_failure(format!("cannot compile guest module: {e}")))?;
        Ok(Self { engine, module })
    }

    fn format_code(format: FileFormat) -> Result<u32, DomainError> {
        match format {
            FileFormat::Png => Ok(FORMAT_PNG),
            other => Err(DomainError::UnsupportedFormat(other)),
        }
    }

    fn options(policy: &Policy) -> u32 {
        let mut bits = 0;
        if policy.strip_metadata {
            bits |= FLAG_STRIP_METADATA;
        }
        bits
    }

    fn to_output(decoded: DecodedResult) -> Result<DisarmOutput, DomainError> {
        match decoded {
            DecodedResult::Ok { bytes, removed } => {
                let removed = removed.iter().map(png_removed_item).collect();
                Ok(DisarmOutput::new(bytes, removed))
            }
            DecodedResult::Malformed(reason) => Err(png_malformed(&reason)),
        }
    }
}

struct GuestAbi {
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    dealloc: TypedFunc<(u32, u32), ()>,
    disarm: TypedFunc<(u32, u32, u32, u32), u64>,
}

impl GuestAbi {
    fn from_instance(
        store: &mut Store<HostState>,
        instance: &Instance,
    ) -> Result<Self, DomainError> {
        let memory = instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| sandbox_failure("guest exports no `memory`"))?;
        let getf = |store: &mut Store<HostState>, name: &str| -> Result<_, DomainError> {
            instance
                .get_func(&mut *store, name)
                .ok_or_else(|| sandbox_failure(format!("guest exports no `{name}`")))
        };
        let alloc = getf(store, "alloc")?
            .typed(&*store)
            .map_err(|e| sandbox_failure(format!("`alloc` has the wrong signature: {e}")))?;
        let dealloc = getf(store, "dealloc")?
            .typed(&*store)
            .map_err(|e| sandbox_failure(format!("`dealloc` has the wrong signature: {e}")))?;
        let disarm = getf(store, "disarm")?
            .typed(&*store)
            .map_err(|e| sandbox_failure(format!("`disarm` has the wrong signature: {e}")))?;
        Ok(Self {
            memory,
            alloc,
            dealloc,
            disarm,
        })
    }

    fn write_input(&self, store: &mut Store<HostState>, data: &[u8]) -> Result<u32, DomainError> {
        let len = u32::try_from(data.len())
            .map_err(|_| sandbox_failure("input too large for the 32-bit sandbox"))?;
        let ptr = self
            .alloc
            .call(&mut *store, len)
            .map_err(|e| sandbox_failure(format!("guest `alloc` trapped: {e}")))?;
        self.memory
            .write(&mut *store, ptr as usize, data)
            .map_err(|e| sandbox_failure(format!("cannot write input into guest memory: {e}")))?;
        Ok(ptr)
    }

    fn read(
        &self,
        store: &mut Store<HostState>,
        ptr: u32,
        len: u32,
    ) -> Result<Vec<u8>, DomainError> {
        let mut buf = vec![0u8; len as usize];
        self.memory
            .read(&*store, ptr as usize, &mut buf)
            .map_err(|e| sandbox_failure(format!("cannot read result from guest memory: {e}")))?;
        Ok(buf)
    }
}

impl Sandbox for WasmtimeSandbox {
    fn run_disarm(
        &self,
        format: FileFormat,
        input: &[u8],
        policy: &Policy,
    ) -> Result<DisarmOutput, DomainError> {
        let format_code = Self::format_code(format)?;
        let options = Self::options(policy);

        let limits = StoreLimitsBuilder::new()
            .memory_size(MAX_GUEST_MEMORY)
            .instances(1)
            .tables(1)
            .build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|state| state);
        store
            .set_fuel(FUEL_BUDGET)
            .map_err(|e| sandbox_failure(format!("cannot set fuel budget: {e}")))?;

        let linker: Linker<HostState> = Linker::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| sandbox_failure(format!("cannot instantiate guest: {e}")))?;

        let abi = GuestAbi::from_instance(&mut store, &instance)?;

        let input_ptr = abi.write_input(&mut store, input)?;
        let packed = abi
            .disarm
            .call(
                &mut store,
                (input_ptr, input.len() as u32, format_code, options),
            )
            .map_err(|e| sandbox_failure(format!("guest `disarm` trapped: {e}")))?;

        abi.dealloc
            .call(&mut store, (input_ptr, input.len() as u32))
            .map_err(|e| sandbox_failure(format!("guest `dealloc` trapped: {e}")))?;

        let result_ptr = (packed >> 32) as u32;
        let result_len = (packed & 0xFFFF_FFFF) as u32;

        let cap = result_len_cap(input.len());
        if result_len as usize > cap {
            return Err(sandbox_failure(format!(
                "guest result length {result_len} exceeds the {cap}-byte cap"
            )));
        }
        let encoded = abi.read(&mut store, result_ptr, result_len)?;
        abi.dealloc
            .call(&mut store, (result_ptr, result_len))
            .map_err(|e| sandbox_failure(format!("guest `dealloc` trapped: {e}")))?;

        let decoded = decode_result(&encoded)
            .map_err(|e| sandbox_failure(format!("guest returned an undecodable result: {e:?}")))?;
        Self::to_output(decoded)
    }
}
