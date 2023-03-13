use std::{collections::HashMap, str::FromStr};

use eth_types as zkevm_types;
use ethers::{types as anvil_types, utils::hex};

pub trait Conversion<T> {
    fn to_zkevm_type(&self) -> T;
}

impl Conversion<zkevm_types::U256> for anvil_types::U256 {
    fn to_zkevm_type(&self) -> zkevm_types::U256 {
        let mut new = zkevm_types::U256::zero();
        new.0 = self.0;
        new
    }
}

impl Conversion<zkevm_types::U256> for anvil_types::H256 {
    fn to_zkevm_type(&self) -> zkevm_types::U256 {
        zkevm_types::U256::from_big_endian(self.as_bytes())
    }
}

impl Conversion<zkevm_types::GethExecTrace> for anvil_types::GethTrace {
    fn to_zkevm_type(&self) -> zkevm_types::GethExecTrace {
        if let ethers::types::GethTrace::Known(anvil_trace_frame) = self.to_owned() {
            if let ethers::types::GethTraceFrame::Default(anvil_trace) = anvil_trace_frame {
                zkevm_types::GethExecTrace {
                    gas: zkevm_types::evm_types::Gas(anvil_trace.gas.as_u64()),
                    failed: anvil_trace.failed,
                    return_value: hex::encode(anvil_trace.return_value.as_ref()), // TODO see if 0x adjustment is needed
                    struct_logs: anvil_trace
                        .struct_logs
                        .into_iter()
                        .map(|step| {
                            zkevm_types::GethExecStep {
                                pc: zkevm_types::evm_types::ProgramCounter(
                                    usize::try_from(step.pc).expect("error converting pc"),
                                ),
                                op: zkevm_types::evm_types::OpcodeId::from_str(&step.op.as_str())
                                    .unwrap(),
                                gas: zkevm_types::evm_types::Gas(step.gas),
                                gas_cost: zkevm_types::evm_types::GasCost(step.gas_cost),
                                refund: zkevm_types::evm_types::Gas(
                                    step.refund_counter.unwrap_or(0),
                                ),
                                depth: u16::try_from(step.depth).expect("error converting depth"),
                                error: step.error,
                                stack: zkevm_types::evm_types::Stack(
                                    step.stack
                                        .unwrap_or(Vec::new())
                                        .into_iter()
                                        .map(|w| w.to_zkevm_type())
                                        .collect(),
                                ),
                                memory: zkevm_types::evm_types::Memory::default(), // memory is not enabled
                                storage: {
                                    let tree = step.storage.unwrap_or_default();
                                    let mut hash_map =
                                        HashMap::<zkevm_types::Word, zkevm_types::Word>::new();
                                    for (key, value) in &tree {
                                        hash_map.insert(key.to_zkevm_type(), value.to_zkevm_type());
                                    }
                                    zkevm_types::evm_types::Storage(hash_map)
                                },
                            }
                        })
                        .collect(),
                }
            } else {
                panic!("unknown value in trace")
            }
        } else {
            panic!("unknown value in trace")
        }
    }
}
