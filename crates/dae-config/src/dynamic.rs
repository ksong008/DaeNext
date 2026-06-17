use crate::ast::Function;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum DynamicFunctionValue {
    #[default]
    Nil,
    String(String),
    Function(Function),
    FunctionList(Vec<Function>),
}
