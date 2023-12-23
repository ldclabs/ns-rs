use proc_macro::TokenStream;

mod cql_orm;

/// #[derive(CqlOrm)] derives CqlOrm for struct
/// Works only on simple structs without generics etc
#[proc_macro_derive(CqlOrm)]
pub fn cql_orm(tokens_input: TokenStream) -> TokenStream {
    cql_orm::cql_orm(tokens_input)
}
