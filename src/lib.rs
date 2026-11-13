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

/// Derives a stable `Command` identity for a type.
///
/// The command id is read from a `#[command(id = "...")]` attribute. It is a
/// stable string independent of the Rust type name, so the type can be renamed
/// without changing its wire identity. The u32 discriminant is derived from the
/// id at compile time by the `Command` trait's default.
#[proc_macro_derive(Command, attributes(command))]
pub fn derive_command(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let id = match command_id(&input) {
        Ok(id) => id,
        Err(err) => return err.to_compile_error().into(),
    };

    let mut generics = input.generics.clone();
    for param in generics.type_params_mut() {
        param.bounds.push(syn::parse_quote!(::reprise_net::Message));
    }
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics ::reprise_net::Command for #name #ty_generics #where_clause {
            const ID: &'static str = #id;
        }
    };

    expanded.into()
}

/// Extracts the `id = "..."` value from a `#[command(id = "...")]` attribute.
fn command_id(input: &DeriveInput) -> syn::Result<String> {
    for attr in &input.attrs {
        if !attr.path().is_ident("command") {
            continue;
        }
        let mut id: Option<String> = None;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("id") {
                let value: syn::LitStr = meta.value()?.parse()?;
                id = Some(value.value());
                Ok(())
            } else {
                Err(meta.error("expected `id = \"...\"`"))
            }
        })?;
        if let Some(id) = id {
            return Ok(id);
        }
    }
    Err(syn::Error::new_spanned(
        &input.ident,
        "missing `#[command(id = \"...\")]` attribute",
    ))
}

/// Generates a command-set enum that dispatches on the wire discriminant.
///
/// A command set groups several `Command` types so a peer can decode "which
/// command" into a single matchable enum. Each listed type must implement
/// `Command` (normally via `#[derive(Command)]`); its stable id supplies the
/// discriminant. The macro emits a compile-time assertion that all discriminants
/// in the set are pairwise distinct.
///
/// ```ignore
/// reprise_net::command_set! {
///     /// One request per transaction stream.
///     pub enum ClientCommands {
///         Ping,
///         Echo,
///         ListProducts,
///     }
/// }
/// ```
#[proc_macro]
pub fn command_set(input: TokenStream) -> TokenStream {
    let set = parse_macro_input!(input as CommandSet);
    expand_command_set(&set).into()
}

struct CommandSet {
    attrs: Vec<syn::Attribute>,
    vis: syn::Visibility,
    name: syn::Ident,
    commands: Vec<syn::TypePath>,
}

impl syn::parse::Parse for CommandSet {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let attrs = input.call(syn::Attribute::parse_outer)?;
        let vis = input.parse()?;
        input.parse::<syn::Token![enum]>()?;
        let name = input.parse()?;

        let content;
        syn::braced!(content in input);
        let mut commands = Vec::new();
        while !content.is_empty() {
            commands.push(content.parse()?);
            if content.peek(syn::Token![,]) {
                content.parse::<syn::Token![,]>()?;
            }
        }

        Ok(CommandSet {
            attrs,
            vis,
            name,
            commands,
        })
    }
}

fn expand_command_set(set: &CommandSet) -> proc_macro2::TokenStream {
    let CommandSet {
        attrs,
        vis,
        name,
        commands,
    } = set;

    // Each variant is named after the command type's last path segment.
    let variant_idents: Vec<syn::Ident> = commands
        .iter()
        .map(|path| {
            path.path
                .segments
                .last()
                .map(|seg| seg.ident.clone())
                .expect("command type path has at least one segment")
        })
        .collect();

    let variants = variant_idents.iter().zip(commands.iter()).map(|(variant, ty)| {
        quote! { #variant(#ty) }
    });

    let encode_arms = variant_idents.iter().zip(commands.iter()).map(|(variant, ty)| {
        quote! {
            #name::#variant(inner) => ::reprise_net::Packet::encode::<#ty>(inner)
        }
    });

    let decode_arms = variant_idents.iter().zip(commands.iter()).map(|(variant, ty)| {
        quote! {
            if packet.discriminant == <#ty as ::reprise_net::Command>::DISCRIMINANT {
                let inner: #ty = packet.decode()?;
                return Ok(#name::#variant(inner));
            }
        }
    });

    // Compile-time check that all discriminants in the set are pairwise distinct.
    let uniqueness = commands.iter().enumerate().flat_map(|(i, a)| {
        commands[i + 1..].iter().map(move |b| {
            quote! {
                assert!(
                    <#a as ::reprise_net::Command>::DISCRIMINANT
                        != <#b as ::reprise_net::Command>::DISCRIMINANT,
                    "command set has a discriminant collision between two commands"
                );
            }
        })
    });

    quote! {
        #(#attrs)*
        #[derive(Debug, Clone)]
        #vis enum #name {
            #(#variants),*
        }

        impl #name {
            /// Encodes the wrapped command into a [`Packet`], carrying its
            /// discriminant and type hash.
            ///
            /// [`Packet`]: ::reprise_net::Packet
            pub fn encode(&self) -> ::core::result::Result<::reprise_net::Packet, ::reprise_net::PacketError> {
                match self {
                    #(#encode_arms),*
                }
            }

            /// Decodes a [`Packet`] into this set by matching its discriminant,
            /// verifying the command's layout hash before decoding the body.
            ///
            /// Returns [`PacketError::UnknownCommand`] if the discriminant is not
            /// in this set.
            ///
            /// [`Packet`]: ::reprise_net::Packet
            /// [`PacketError::UnknownCommand`]: ::reprise_net::PacketError::UnknownCommand
            pub fn decode(packet: &::reprise_net::Packet) -> ::core::result::Result<Self, ::reprise_net::PacketError> {
                #(#decode_arms)*
                Err(::reprise_net::PacketError::UnknownCommand(packet.discriminant))
            }
        }

        const _: () = {
            #(#uniqueness)*
        };
    }
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
