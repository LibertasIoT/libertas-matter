// Copyright (c) 2026 Smartonlabs Inc.
// SPDX-License-Identifier: MIT

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, LitInt, LitStr, Type, parse::ParseStream};

#[derive(Clone)]
struct Arguments {
    start: u8,
    datatype: String,
}

impl Default for Arguments {
    fn default() -> Self {
        Self {
            start: 0,
            datatype: String::from("struct"),
        }
    }
}

fn arguments(input: &DeriveInput) -> Arguments {
    let mut result = Arguments::default();
    for attribute in input
        .attrs
        .iter()
        .filter(|attribute| attribute.path().is_ident("tlvargs"))
    {
        attribute
            .parse_nested_meta(|meta| {
                if meta.path.is_ident("start") {
                    result.start = meta.value()?.parse::<LitInt>()?.base10_parse()?;
                } else if meta.path.is_ident("datatype") {
                    result.datatype = meta.value()?.parse::<LitStr>()?.value();
                } else if meta.path.is_ident("unordered") || meta.path.is_ident("lifetime") {
                    if meta.path.is_ident("lifetime") {
                        let _ = meta.value()?.parse::<LitStr>()?;
                    }
                } else {
                    return Err(meta.error("unsupported TLV argument"));
                }
                Ok(())
            })
            .unwrap_or_else(|error| panic!("{error}"));
    }
    result
}

fn field_tag(field: &syn::Field, fallback: u8) -> u8 {
    for attribute in &field.attrs {
        if attribute.path().is_ident("tagval") {
            return attribute
                .parse_args_with(|input: ParseStream<'_>| {
                    input.parse::<LitInt>()?.base10_parse::<u8>()
                })
                .unwrap_or_else(|error| panic!("{error}"));
        }
    }
    fallback
}

fn variant_value(variant: &syn::Variant, fallback: u16) -> u16 {
    for attribute in &variant.attrs {
        if attribute.path().is_ident("enumval") {
            return attribute
                .parse_args_with(|input: ParseStream<'_>| {
                    input.parse::<LitInt>()?.base10_parse::<u16>()
                })
                .unwrap_or_else(|error| panic!("{error}"));
        }
    }
    fallback
}

pub(crate) fn derive_to_tlv(input: DeriveInput, runtime: TokenStream) -> TokenStream {
    let name = &input.ident;
    let args = arguments(&input);
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    let nullable_body = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => Some(quote! {
                #runtime::tlv::ToTLV::nullable_to_tlv(&self.0, tag, writer)
            }),
            _ => None,
        },
        _ => None,
    };
    let nullable_method = nullable_body.map(|body| {
        quote! {
            fn nullable_to_tlv<W: #runtime::tlv::TLVWrite + ?Sized>(
                &self,
                tag: #runtime::tlv::Tag,
                writer: &mut W,
            ) -> Result<(), #runtime::error::Error> {
                #body
            }
        }
    });

    let body = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => quote! {
                #runtime::tlv::ToTLV::to_tlv(&self.0, tag, writer)
            },
            Fields::Named(fields) => {
                let mut next = args.start;
                let writes = fields.named.iter().map(|field| {
                    let field_name = field.ident.as_ref().expect("named field");
                    let tag = field_tag(field, next);
                    next = tag.checked_add(1).unwrap_or(tag);
                    quote! {
                        #runtime::tlv::ToTLV::to_tlv(
                            &self.#field_name,
                            #runtime::tlv::Tag::Context(#tag),
                            writer,
                        )?;
                    }
                });
                quote! {
                    #runtime::tlv::transaction(writer, |writer| {
                        writer.start_struct(tag)?;
                        #(#writes)*
                        writer.end_container()
                    })
                }
            }
            Fields::Unit => quote! {
                #runtime::tlv::transaction(writer, |writer| {
                    writer.start_struct(tag)?;
                    writer.end_container()
                })
            },
            _ => quote!(compile_error!(
                "tuple TLV structs must contain exactly one field"
            )),
        },
        Data::Enum(data) => {
            let all_unit = data
                .variants
                .iter()
                .all(|variant| matches!(variant.fields, Fields::Unit));
            if all_unit {
                let mut next = args.start as u16;
                let arms = data.variants.iter().map(|variant| {
                    let variant_name = &variant.ident;
                    let value = variant_value(variant, next);
                    next = value.saturating_add(1);
                    match args.datatype.as_str() {
                        "u16" => quote!(Self::#variant_name => writer.u16(tag, #value),),
                        "u8" | "struct" => {
                            let value = u8::try_from(value)
                                .expect("u8 TLV enum value exceeds the u8 domain");
                            quote!(Self::#variant_name => writer.u8(tag, #value),)
                        }
                        _ => panic!("TLV unit enum datatype must be u8 or u16"),
                    }
                });
                quote! {
                    match self {
                        #(#arms)*
                    }
                }
            } else {
                let mut next = args.start;
                let arms = data.variants.iter().map(|variant| {
                    let variant_name = &variant.ident;
                    let tag = variant_value(variant, next as u16);
                    next = u8::try_from(tag.saturating_add(1)).unwrap_or(next);
                    let tag = u8::try_from(tag).expect("variant context tag exceeds u8");
                    match &variant.fields {
                        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => quote! {
                            Self::#variant_name(value) => {
                                #runtime::tlv::ToTLV::to_tlv(
                                    value,
                                    #runtime::tlv::Tag::Context(#tag),
                                    writer,
                                )?;
                            }
                        },
                        _ => quote!(compile_error!(
                            "data TLV enums require one-field tuple variants"
                        )),
                    }
                });
                quote! {
                    #runtime::tlv::transaction(writer, |writer| {
                        writer.start_struct(tag)?;
                        match self {
                            #(#arms)*
                        }
                        writer.end_container()
                    })
                }
            }
        }
        Data::Union(_) => quote!(compile_error!("TLV unions are not supported")),
    };

    quote! {
        impl #impl_generics #runtime::tlv::ToTLV for #name #type_generics #where_clause {
            fn to_tlv<W: #runtime::tlv::TLVWrite + ?Sized>(
                &self,
                tag: #runtime::tlv::Tag,
                writer: &mut W,
            ) -> Result<(), #runtime::error::Error> {
                use #runtime::tlv::TLVWrite as _;
                #body
            }

            #nullable_method
        }
    }
}

pub(crate) fn derive_from_tlv(input: DeriveInput, runtime: TokenStream) -> TokenStream {
    let name = &input.ident;
    let args = arguments(&input);
    let (_, type_generics, where_clause) = input.generics.split_for_impl();
    let mut decode_generics = input.generics.clone();
    decode_generics
        .params
        .insert(0, syn::parse_quote!('__matter_tlv));
    let (decode_impl_generics, _, _) = decode_generics.split_for_impl();

    let nullable_body = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let field_type = &fields.unnamed[0].ty;
                Some(quote! {
                    Ok(Self(
                        <#field_type as #runtime::tlv::FromTLV>::nullable_from_tlv(element)?
                    ))
                })
            }
            _ => None,
        },
        _ => None,
    };
    let nullable_method = nullable_body.map(|body| {
        quote! {
            fn nullable_from_tlv(
                element: &#runtime::tlv::Element<'__matter_tlv>,
            ) -> Result<Self, #runtime::error::Error> {
                #body
            }
        }
    });

    let body = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                let field_type = &fields.unnamed[0].ty;
                quote! {
                    Ok(Self(<#field_type as #runtime::tlv::FromTLV>::from_tlv(element)?))
                }
            }
            Fields::Named(fields) => {
                let mut next = args.start;
                let decodes = fields.named.iter().map(|field| {
                    let field_name = field.ident.as_ref().expect("named field");
                    let field_type = &field.ty;
                    let tag = field_tag(field, next);
                    next = tag.checked_add(1).unwrap_or(tag);
                    if let Some(inner) = option_inner(field_type) {
                        quote! {
                            #field_name: match element.get(#runtime::tlv::Tag::Context(#tag))? {
                                Some(value) => Some(
                                    <#inner as #runtime::tlv::FromTLV>::from_tlv(&value)?
                                ),
                                None => None,
                            }
                        }
                    } else {
                        quote! {
                            #field_name: <#field_type as #runtime::tlv::FromTLV>::from_tlv(
                                &element.context(#tag)?
                            )?
                        }
                    }
                });
                quote! {
                    if element.value_type() != #runtime::tlv::ValueType::Structure {
                        return Err(#runtime::error::Error::TypeMismatch);
                    }
                    Ok(Self { #(#decodes),* })
                }
            }
            Fields::Unit => quote! {
                if element.value_type() != #runtime::tlv::ValueType::Structure {
                    Err(#runtime::error::Error::TypeMismatch)
                } else {
                    Ok(Self)
                }
            },
            _ => quote!(compile_error!(
                "tuple TLV structs must contain exactly one field"
            )),
        },
        Data::Enum(data) => {
            let all_unit = data
                .variants
                .iter()
                .all(|variant| matches!(variant.fields, Fields::Unit));
            if all_unit {
                let mut next = args.start as u16;
                let arms = data.variants.iter().map(|variant| {
                    let variant_name = &variant.ident;
                    let value = variant_value(variant, next);
                    next = value.saturating_add(1);
                    quote!(#value => Ok(Self::#variant_name),)
                });
                let read = match args.datatype.as_str() {
                    "u16" => quote!(element.u16()?),
                    "u8" | "struct" => quote!(element.u8()? as u16),
                    _ => panic!("TLV unit enum datatype must be u8 or u16"),
                };
                quote! {
                    match #read {
                        #(#arms)*
                        _ => Err(#runtime::error::Error::OutOfRange),
                    }
                }
            } else {
                let mut next = args.start;
                let arms = data.variants.iter().map(|variant| {
                    let variant_name = &variant.ident;
                    let tag = variant_value(variant, next as u16);
                    next = u8::try_from(tag.saturating_add(1)).unwrap_or(next);
                    let tag = u8::try_from(tag).expect("variant context tag exceeds u8");
                    match &variant.fields {
                        Fields::Unnamed(fields) if fields.unnamed.len() == 1 => {
                            let field_type = &fields.unnamed[0].ty;
                            quote! {
                                if let Some(value) = element.get(#runtime::tlv::Tag::Context(#tag))? {
                                    return Ok(Self::#variant_name(
                                        <#field_type as #runtime::tlv::FromTLV>::from_tlv(&value)?
                                    ));
                                }
                            }
                        }
                        _ => quote!(compile_error!("data TLV enums require one-field tuple variants")),
                    }
                });
                quote! {
                    if element.value_type() != #runtime::tlv::ValueType::Structure {
                        return Err(#runtime::error::Error::TypeMismatch);
                    }
                    #(#arms)*
                    Err(#runtime::error::Error::TypeMismatch)
                }
            }
        }
        Data::Union(_) => quote!(compile_error!("TLV unions are not supported")),
    };

    quote! {
        impl #decode_impl_generics #runtime::tlv::FromTLV<'__matter_tlv>
            for #name #type_generics #where_clause
        {
            fn from_tlv(
                element: &#runtime::tlv::Element<'__matter_tlv>,
            ) -> Result<Self, #runtime::error::Error> {
                #body
            }

            #nullable_method
        }
    }
}

fn option_inner(field_type: &Type) -> Option<&Type> {
    let Type::Path(path) = field_type else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Option" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    match arguments.args.first()? {
        syn::GenericArgument::Type(inner) => Some(inner),
        _ => None,
    }
}
