// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

//! Direct writer derives and generated-definition binding macros.

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro_crate::{FoundCrate, crate_name};
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{
    DeriveInput, Expr, Fields, Item, ItemMod, Result, Token,
    parse::{Parse, ParseStream},
    parse_macro_input, parse_quote,
};

mod tlv;

#[proc_macro_derive(ToTLV, attributes(tlvargs, tagval, enumval))]
pub fn derive_to_tlv(input: TokenStream) -> TokenStream {
    tlv::derive_to_tlv(parse_macro_input!(input as DeriveInput), runtime_path()).into()
}

#[proc_macro_derive(FromTLV, attributes(tlvargs, tagval, enumval))]
pub fn derive_from_tlv(input: TokenStream) -> TokenStream {
    tlv::derive_from_tlv(parse_macro_input!(input as DeriveInput), runtime_path()).into()
}

#[proc_macro_attribute]
pub fn matter_tlv(_: TokenStream, item: TokenStream) -> TokenStream {
    expand_definition(item, None)
}

#[proc_macro_attribute]
pub fn matter_attribute(args: TokenStream, item: TokenStream) -> TokenStream {
    expand_definition(
        item,
        Some(DefinitionKind::Attribute(parse_macro_input!(
            args as DefinitionArgs
        ))),
    )
}

#[proc_macro_attribute]
pub fn matter_command(args: TokenStream, item: TokenStream) -> TokenStream {
    expand_definition(
        item,
        Some(DefinitionKind::Command(parse_macro_input!(
            args as DefinitionArgs
        ))),
    )
}

#[proc_macro_attribute]
pub fn matter_event(args: TokenStream, item: TokenStream) -> TokenStream {
    expand_definition(
        item,
        Some(DefinitionKind::Event(parse_macro_input!(
            args as DefinitionArgs
        ))),
    )
}

#[proc_macro]
pub fn matter_attributes(input: TokenStream) -> TokenStream {
    expand_ids(input)
}

#[proc_macro]
pub fn matter_commands(input: TokenStream) -> TokenStream {
    expand_ids(input)
}

#[proc_macro]
pub fn matter_events(input: TokenStream) -> TokenStream {
    expand_ids(input)
}

fn runtime_path() -> TokenStream2 {
    match crate_name("libertas-matter") {
        Ok(FoundCrate::Itself) => quote!(crate),
        Ok(FoundCrate::Name(name)) => {
            let ident = syn::Ident::new(&name, proc_macro2::Span::call_site());
            quote!(::#ident)
        }
        Err(_) => quote!(::libertas_matter),
    }
}

#[derive(Default)]
struct DefinitionArgs {
    cluster: Option<Expr>,
    id: Option<Expr>,
    readable: Option<Expr>,
    writable: Option<Expr>,
    response: Option<Expr>,
    response_id: Option<Expr>,
}

impl Parse for DefinitionArgs {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut result = Self::default();
        while !input.is_empty() {
            let name: syn::Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            let value: Expr = input.parse()?;
            match name.to_string().as_str() {
                "cluster" => result.cluster = Some(value),
                "id" => result.id = Some(value),
                "readable" => result.readable = Some(value),
                "writable" => result.writable = Some(value),
                "response" => result.response = Some(value),
                "response_id" => result.response_id = Some(value),
                _ => return Err(syn::Error::new_spanned(name, "unsupported Matter argument")),
            }
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }
        Ok(result)
    }
}

enum DefinitionKind {
    Attribute(DefinitionArgs),
    Command(DefinitionArgs),
    Event(DefinitionArgs),
}

fn expand_definition(item: TokenStream, kind: Option<DefinitionKind>) -> TokenStream {
    let original = parse_macro_input!(item as DeriveInput);
    let mut emitted = original.clone();
    strip_helper_attributes(&mut emitted);
    let runtime = runtime_path();
    let to_tlv = tlv::derive_to_tlv(original.clone(), runtime.clone());
    let from_tlv = tlv::derive_from_tlv(original.clone(), runtime.clone());
    let name = &original.ident;
    let (impl_generics, type_generics, where_clause) = original.generics.split_for_impl();

    let descriptor = match kind {
        None => quote!(),
        Some(DefinitionKind::Attribute(args)) => {
            let cluster = match required(args.cluster, &original, "cluster") {
                Ok(value) => value,
                Err(error) => return error.into(),
            };
            let id = match required(args.id, &original, "id") {
                Ok(value) => value,
                Err(error) => return error.into(),
            };
            let readable = args.readable.unwrap_or_else(|| parse_quote!(true));
            let writable = args.writable.unwrap_or_else(|| parse_quote!(false));
            quote! {
                impl #impl_generics #runtime::MatterAttribute for #name #type_generics #where_clause {
                    const CLUSTER_ID: u32 = #cluster;
                    const ID: u32 = #id;
                    const READABLE: bool = #readable;
                    const WRITABLE: bool = #writable;
                }
            }
        }
        Some(DefinitionKind::Command(args)) => {
            let cluster = match required(args.cluster, &original, "cluster") {
                Ok(value) => value,
                Err(error) => return error.into(),
            };
            let id = match required(args.id, &original, "id") {
                Ok(value) => value,
                Err(error) => return error.into(),
            };
            let response = args.response.unwrap_or_else(|| parse_quote!(()));
            let response_id = match args.response_id {
                Some(id) => quote!(Some(#id)),
                None => quote!(None),
            };
            quote! {
                impl #impl_generics #runtime::MatterCommand for #name #type_generics #where_clause {
                    type Response = #response;
                    const CLUSTER_ID: u32 = #cluster;
                    const ID: u32 = #id;
                    const RESPONSE_ID: Option<u32> = #response_id;
                }
            }
        }
        Some(DefinitionKind::Event(args)) => {
            let cluster = match required(args.cluster, &original, "cluster") {
                Ok(value) => value,
                Err(error) => return error.into(),
            };
            let id = match required(args.id, &original, "id") {
                Ok(value) => value,
                Err(error) => return error.into(),
            };
            quote! {
                impl #impl_generics #runtime::MatterEvent for #name #type_generics #where_clause {
                    const CLUSTER_ID: u32 = #cluster;
                    const ID: u32 = #id;
                }
            }
        }
    };

    quote!(#emitted #to_tlv #from_tlv #descriptor).into()
}

fn required(
    value: Option<Expr>,
    item: &DeriveInput,
    argument: &str,
) -> core::result::Result<Expr, TokenStream2> {
    value.ok_or_else(|| {
        syn::Error::new_spanned(item, format!("missing `{argument}` argument")).into_compile_error()
    })
}

fn strip_helper_attributes(item: &mut DeriveInput) {
    item.attrs
        .retain(|attribute| !attribute.path().is_ident("tlvargs"));
    let strip_fields = |fields: &mut Fields| {
        for field in fields {
            field
                .attrs
                .retain(|attribute| !attribute.path().is_ident("tagval"));
        }
    };
    match &mut item.data {
        syn::Data::Struct(data) => strip_fields(&mut data.fields),
        syn::Data::Enum(data) => {
            for variant in &mut data.variants {
                variant
                    .attrs
                    .retain(|attribute| !attribute.path().is_ident("enumval"));
                strip_fields(&mut variant.fields);
            }
        }
        syn::Data::Union(_) => {}
    }
}

struct Modules(Vec<ItemMod>);

impl Parse for Modules {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut modules = Vec::new();
        while !input.is_empty() {
            modules.push(input.parse()?);
        }
        Ok(Self(modules))
    }
}

fn expand_ids(input: TokenStream) -> TokenStream {
    let Modules(modules) = parse_macro_input!(input as Modules);
    let mut emitted_modules = Vec::new();
    let mut module_catalogs = Vec::new();

    for module in modules {
        let attributes = module.attrs;
        let visibility = module.vis;
        let name = module.ident;
        let Some((_, items)) = module.content else {
            return syn::Error::new_spanned(name, "generated ID modules must be inline")
                .into_compile_error()
                .into();
        };
        let mut entries = Vec::new();
        for item in &items {
            let Item::Const(constant) = item else {
                return syn::Error::new_spanned(item, "ID modules may contain only constants")
                    .into_compile_error()
                    .into();
            };
            let constant_name = &constant.ident;
            entries.push(quote!((stringify!(#constant_name), #constant_name)));
        }
        emitted_modules.push(quote! {
            #(#attributes)*
            #visibility mod #name {
                #(#items)*
                pub const ALL: &[(&str, u32)] = &[#(#entries),*];
            }
        });
        module_catalogs.push(quote!((stringify!(#name), #name::ALL)));
    }

    quote! {
        #(#emitted_modules)*
        pub const ALL: &[(&str, &[(&str, u32)])] = &[#(#module_catalogs),*];
    }
    .into()
}
