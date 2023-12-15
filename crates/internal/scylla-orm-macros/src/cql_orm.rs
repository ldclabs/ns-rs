use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, FieldsNamed};

/// #[proc_macro_derive(CqlOrm)]
pub fn cql_orm(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);

    let struct_name = &ast.ident;
    let fields = match ast.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(FieldsNamed { named, .. }) => named,
            _ => panic!("CqlOrm can only be derived for structs with named fields"),
        },
        _ => panic!("CqlOrm can only be derived for structs"),
    };

    // Filter out fields that start with an underscore.
    let fields_filtered = fields
        .into_iter()
        .filter(|f| {
            let name = &f.ident.as_ref().unwrap().to_string();
            !name.starts_with('_')
        })
        .collect::<Vec<_>>();
    let fields_num = fields_filtered.len();

    let field_names0 = fields_filtered.iter().map(|f| &f.ident);
    let field_names1 = field_names0.clone();
    let field_names_string0 = fields_filtered
        .iter()
        .map(|f| f.ident.as_ref().unwrap().to_string());
    let field_names_string1 = field_names_string0.clone();
    let field_names_string2 = field_names_string0.clone();
    let field_names_string3 = field_names_string0.clone();

    let expanded = quote! {
        impl #struct_name {
            pub fn fields() -> Vec<String> {
                vec![
                    #(#field_names_string0.to_string()),*
                ]
            }

            pub fn fill(&mut self, cols: &scylla_orm::ColumnsMap) {
                #(
                    if cols.has(#field_names_string1) {
                        self.#field_names0 = cols.get_as(#field_names_string2).unwrap_or_default();
                    }
                )*
            }

            pub fn to(&self) -> scylla_orm::ColumnsMap {
                let mut cols = scylla_orm::ColumnsMap::with_capacity(#fields_num);
                #(
                    cols.set_as(#field_names_string3, &self.#field_names1);
                )*
                cols
            }
        }
    };

    TokenStream::from(expanded)
}
