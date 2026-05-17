use crate::ast::Function;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DynamicFunctionValue {
    Nil,
    String(String),
    Function(Function),
    FunctionList(Vec<Function>),
}

impl Default for DynamicFunctionValue {
    fn default() -> Self {
        Self::Nil
    }
}
