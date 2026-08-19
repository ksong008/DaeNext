use super::*;

pub(crate) struct Borrowed<'a, T>(&'a T);
pub(crate) struct Owned<T>(T);

pub(crate) fn borrowed<T>(value: &T) -> Borrowed<'_, T> {
    Borrowed(value)
}

pub(crate) fn owned<T>(value: T) -> Owned<T> {
    Owned(value)
}

pub(crate) trait ValueInput<T: Clone> {
    fn get(&self) -> &T;
    fn take(self) -> T;
}

impl<T: Clone> ValueInput<T> for Borrowed<'_, T> {
    #[inline(always)]
    fn get(&self) -> &T {
        self.0
    }

    #[inline(always)]
    fn take(self) -> T {
        self.0.clone()
    }
}

impl<T: Clone> ValueInput<T> for Owned<T> {
    #[inline(always)]
    fn get(&self) -> &T {
        &self.0
    }

    #[inline(always)]
    fn take(self) -> T {
        self.0
    }
}

pub(crate) struct SectionInput<'a, M: InputMode> {
    pub(super) name: M::Value<'a, String>,
    pub(super) items: M::Items<'a>,
}

pub(crate) enum ItemInput<'a, M: InputMode> {
    Param(M::Value<'a, Param>),
    Section(M::Value<'a, Section>),
    RoutingRule(M::Value<'a, RoutingRule>),
}

impl<'a, M: InputMode> ItemInput<'a, M> {
    pub(super) const fn kind(&self) -> crate::ast::ItemKind {
        match self {
            Self::Param(_) => crate::ast::ItemKind::Param,
            Self::Section(_) => crate::ast::ItemKind::Section,
            Self::RoutingRule(_) => crate::ast::ItemKind::RoutingRule,
        }
    }

    pub(super) fn to_config_string(&self, compact: bool, quote_val: bool) -> String {
        match self {
            Self::Param(param) => {
                Item::Param(param.get().clone()).to_config_string(compact, quote_val)
            }
            Self::Section(section) => {
                Item::Section(Box::new(section.get().clone())).to_config_string(compact, quote_val)
            }
            Self::RoutingRule(rule) => {
                Item::RoutingRule(rule.get().clone()).to_config_string(compact, quote_val)
            }
        }
    }
}

pub(crate) struct ParamInput<'a, M: InputMode> {
    pub(super) key: M::Value<'a, String>,
    pub(super) val: M::Value<'a, String>,
    pub(super) and_functions: M::Value<'a, Vec<Function>>,
    pub(super) annotation: M::Value<'a, Vec<Param>>,
}

pub(crate) trait InputMode: Sized {
    type Value<'a, T: Clone + 'a>: ValueInput<T>;
    type Items<'a>: Iterator<Item = Self::Value<'a, Item>>;

    fn section_parts<'a>(section: Self::Value<'a, Section>) -> SectionInput<'a, Self>;
    fn item_parts<'a>(item: Self::Value<'a, Item>) -> ItemInput<'a, Self>;
    fn param_parts<'a>(param: Self::Value<'a, Param>) -> ParamInput<'a, Self>;
}

pub(crate) struct BorrowedMode;

pub(crate) struct BorrowedItems<'a>(std::slice::Iter<'a, Item>);

impl<'a> Iterator for BorrowedItems<'a> {
    type Item = Borrowed<'a, Item>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Borrowed)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl InputMode for BorrowedMode {
    type Value<'a, T: Clone + 'a> = Borrowed<'a, T>;
    type Items<'a> = BorrowedItems<'a>;

    #[inline(always)]
    fn section_parts<'a>(section: Self::Value<'a, Section>) -> SectionInput<'a, Self> {
        SectionInput {
            name: Borrowed(&section.0.name),
            items: BorrowedItems(section.0.items.iter()),
        }
    }

    #[inline(always)]
    fn item_parts<'a>(item: Self::Value<'a, Item>) -> ItemInput<'a, Self> {
        match item.0 {
            Item::Param(param) => ItemInput::Param(Borrowed(param)),
            Item::Section(section) => ItemInput::Section(Borrowed(section.as_ref())),
            Item::RoutingRule(rule) => ItemInput::RoutingRule(Borrowed(rule)),
        }
    }

    #[inline(always)]
    fn param_parts<'a>(param: Self::Value<'a, Param>) -> ParamInput<'a, Self> {
        ParamInput {
            key: Borrowed(&param.0.key),
            val: Borrowed(&param.0.val),
            and_functions: Borrowed(&param.0.and_functions),
            annotation: Borrowed(&param.0.annotation),
        }
    }
}

pub(crate) struct OwnedMode;

pub(crate) struct OwnedItems(std::vec::IntoIter<Item>);

impl Iterator for OwnedItems {
    type Item = Owned<Item>;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Owned)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl InputMode for OwnedMode {
    type Value<'a, T: Clone + 'a> = Owned<T>;
    type Items<'a> = OwnedItems;

    #[inline(always)]
    fn section_parts<'a>(section: Self::Value<'a, Section>) -> SectionInput<'a, Self> {
        SectionInput {
            name: Owned(section.0.name),
            items: OwnedItems(section.0.items.into_iter()),
        }
    }

    #[inline(always)]
    fn item_parts<'a>(item: Self::Value<'a, Item>) -> ItemInput<'a, Self> {
        match item.0 {
            Item::Param(param) => ItemInput::Param(Owned(param)),
            Item::Section(section) => ItemInput::Section(Owned(*section)),
            Item::RoutingRule(rule) => ItemInput::RoutingRule(Owned(rule)),
        }
    }

    #[inline(always)]
    fn param_parts<'a>(param: Self::Value<'a, Param>) -> ParamInput<'a, Self> {
        ParamInput {
            key: Owned(param.0.key),
            val: Owned(param.0.val),
            and_functions: Owned(param.0.and_functions),
            annotation: Owned(param.0.annotation),
        }
    }
}
