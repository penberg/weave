use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse_macro_input, ItemFn};

/// Marks a function as a Weave libc symbol override.
///
/// This attribute macro:
/// 1. Renames `fn foo` to `fn weave_foo`
/// 2. Adds `#[unsafe(no_mangle)]` and `extern "C"`
/// 3. Registers the symbol mapping `_foo` -> `weave_foo`
///
/// # Example
///
/// ```ignore
/// #[weave_symbol]
/// pub fn dlopen(path: *const libc::c_char, flags: libc::c_int) -> *mut libc::c_void {
///     // implementation
/// }
/// ```
///
/// Expands to:
///
/// ```ignore
/// #[unsafe(no_mangle)]
/// pub extern "C" fn weave_dlopen(path: *const libc::c_char, flags: libc::c_int) -> *mut libc::c_void {
///     // implementation
/// }
///
/// #[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
/// static _WEAVE_SYM_DLOPEN: (&str, usize) = ("_dlopen", weave_dlopen as usize);
/// ```
#[proc_macro_attribute]
pub fn weave_symbol(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);

    let vis = &input.vis;
    let sig = &input.sig;
    let block = &input.block;
    let attrs = &input.attrs;

    let original_name = &sig.ident;
    let weave_name = format_ident!("weave_{}", original_name);
    let symbol_name = format!("_{}", original_name);
    let static_name = format_ident!("_WEAVE_SYM_{}", original_name.to_string().to_uppercase());

    let inputs = &sig.inputs;
    let output = &sig.output;

    let expanded = quote! {
        #(#attrs)*
        #[unsafe(no_mangle)]
        #vis extern "C" fn #weave_name(#inputs) #output #block

        #[linkme::distributed_slice(crate::symbols::WEAVE_SYMBOLS)]
        static #static_name: (&str, crate::symbols::FnPtr) =
            (#symbol_name, crate::symbols::FnPtr(#weave_name as *const ()));
    };

    TokenStream::from(expanded)
}
