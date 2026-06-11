#[cfg(all(feature = "allocator-system", feature = "allocator-jemalloc"))]
compile_error!("allocator-system cannot be combined with allocator-jemalloc");

#[cfg(feature = "allocator-jemalloc")]
#[global_allocator]
static GLOBAL_ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
