//! IBC middleware that sends amounts overflowing some target to another address.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(test, deny(clippy::assertions_on_result_states))]
#![cfg_attr(
    not(test),
    deny(
        missing_docs,
        rust_2018_idioms,
        clippy::string_to_string,
        clippy::std_instead_of_core,
        clippy::string_add,
        clippy::str_to_string,
        clippy::infinite_loop,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cfg_not_test,
        clippy::as_conversions,
        clippy::alloc_instead_of_core,
        clippy::float_arithmetic,
        clippy::empty_docs,
        clippy::empty_line_after_doc_comments,
        clippy::empty_line_after_outer_attr,
        clippy::suspicious_doc_comments,
        clippy::redundant_locals,
        clippy::redundant_comparisons,
        clippy::out_of_bounds_indexing,
        clippy::empty_loop,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_lossless,
        clippy::arithmetic_side_effects,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::shadow_unrelated,
        clippy::useless_attribute,
        clippy::zero_repeat_side_effects,
        clippy::builtin_type_shadow,
        clippy::unreachable
    )
)]
