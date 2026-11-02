//! Derives a stable [`Layout`] fingerprint for a type.
//!
//! The generated `TYPE_HASH` folds the type's own name together with the
//! `TYPE_HASH` of each field type, so composite types recurse automatically: a
//! struct's fingerprint embeds the fingerprints of its fields, which embed
//! theirs, all collapsed to a single `const` at compile time.
//!
//! The fold mirrors what bincode actually emits: struct fields are folded in
//! declaration order (field names are not included, since the wire is name-free),
//! and enum variants are folded in declaration order because bincode encodes the
//! variant index positionally.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, parse_macro_input};

#[proc_macro_derive(Layout)]
pub fn derive_layout(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let body = match &input.data {
        Data::Struct(data) => body(&type_prefix(&input), &data.fields),
        Data::Enum(data) => {
            let type_name = name.to_string();
            let mut fold = quote! { ::reprise_net::TypeHash::of(#type_name) };
            for variant in &data.variants {
                let vname = variant.ident.to_string();
                let vhash = body(&quote! { #vname }, &variant.fields);
                fold = quote! { #fold.combine(#vhash) };
            }
            fold
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(name, "Layout cannot be derived for unions")
                .to_compile_error()
                .into();
        }
    };

    // Propagate a `Layout` bound onto every generic parameter so that
    // `PatchField<T>`, `Option<T>`, etc. recurse through their type arguments.
    let mut generics = input.generics.clone();
    for param in generics.type_params_mut() {
        param.bounds.push(syn::parse_quote!(::reprise_net::Layout));
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics ::reprise_net::Layout for #name #ty_generics #where_clause {
            const TYPE_HASH: ::reprise_net::TypeHash = #body;
        }
    };

    expanded.into()
}

fn type_prefix(input: &DeriveInput) -> proc_macro2::TokenStream {
    let name = input.ident.to_string();
    quote! { #name }
}

/// Builds the fingerprint fold for a set of fields, prefixed by a label (the
/// struct or variant name).
///
/// Field names are deliberately not folded in: bincode encodes only the field
/// values in declaration order, so a rename does not change the wire.
fn body(prefix: &proc_macro2::TokenStream, fields: &Fields) -> proc_macro2::TokenStream {
    let mut fold = quote! { ::reprise_net::TypeHash::of(#prefix) };
    for field in fields.iter() {
        let ty = &field.ty;
        fold = quote! {
            #fold
                .combine(<#ty as ::reprise_net::Layout>::TYPE_HASH)
        };
    }
    fold
}
