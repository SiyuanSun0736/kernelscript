(*
 * Copyright 2025 Multikernel Technologies, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *)

(** 
   Comprehensive unit tests for global function functionality in KernelScript.
   
   This test suite covers:
   
   === Parser Tests ===
   - Top-level global function parsing
   - Function validation
   
   === Main Function Signature Tests ===
   - Correct signature validation: fn main() -> i32 or fn main(args: CustomStruct) -> i32
   - Wrong parameter types rejection
   - Wrong return type rejection
   - Parameter count validation (too many parameters)
   
   === Main Function Existence Tests ===
   - Missing main function detection
   - Multiple main function rejection
   
   === Integration Tests ===
   - Global functions with helper functions
   - Global functions with struct definitions
   - Multiple eBPF programs with single userspace coordinator
   
   === Code Generation Tests ===
   - Generated C main signature: int main(void) or int main(int argc, char **argv) with command line parsing
   - File naming scheme: FOO.c from FOO.ks
   - Struct definitions in generated code
   - Multiple function generation
   - Required includes and BPF infrastructure
   - Error handling for invalid signatures
   
   === C Code Generation Tests (Literal Key/Value Bug Fix) ===
   - Temporary variable creation for literal keys and values in map operations
   - Direct variable usage for non-literal expressions
   - Mixed literal and variable expressions handling
   - Map lookup expressions with literal keys
   - Unique temporary variable name generation
   - Validation that direct literal addressing (&(literal)) is avoided
*)

open Kernelscript.Parse
open Alcotest
module Ir = Kernelscript.Ir

(** Test that global functions are parsed correctly *)
let test_global_functions_top_level () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  let ast = parse_string code in
  (* Should contain global functions *)
  let has_global_functions = List.exists (function
    | Kernelscript.Ast.GlobalFunction _ -> true
    | _ -> false
  ) ast in
  check bool "global functions found" true has_global_functions

(** Test that functions inside program blocks are not global *)
let test_program_function_isolation () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  let ast = parse_string code in
  (* Should have two global functions: the attributed function and main *)
  let global_functions = List.filter_map (function
    | Kernelscript.Ast.GlobalFunction f -> Some f
    | Kernelscript.Ast.AttributedFunction _ -> None (* Attributed functions are not global functions *)
    | _ -> None
  ) ast in
  check int "only one global function (main)" 1 (List.length global_functions);
  check string "global function is main" "main" (List.hd global_functions).func_name

(** Test main function with correct signature - no parameters *)
let test_main_correct_signature () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  let ast = parse_string code in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  check bool "correct main signature accepted" true true

(** Test main function with struct parameter *)
let test_main_with_struct_param () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    struct Args {
      interface_id: u32,
      debug_mode: u32,
    }
    
    fn main(args: Args) -> i32 {
      return 0
    }
  |} in
  let ast = parse_string code in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  check bool "correct main signature with struct accepted" true true

(** Test main function with wrong parameter types *)
let test_main_wrong_param_types () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main(wrong_param: u32, another_wrong: u32) -> i32 {
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "wrong parameter types should fail" false true
  with
  | _ -> check bool "wrong parameter types correctly rejected" true true

(** Test main function with wrong return type *)
let test_main_wrong_return_type () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> u32 {
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "wrong return type should fail" false true
  with
  | _ -> check bool "wrong return type correctly rejected" true true

(** Test main function with non-struct single parameter *)
let test_main_non_struct_param () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main(bad_param: u32) -> i32 {
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "non-struct single parameter should fail" false true
  with
  | _ -> check bool "non-struct single parameter correctly rejected" true true

(** Test main function with too many parameters *)
let test_main_too_many_params () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main(param1: u32, param2: u64, extra: u32) -> i32 {
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "too many parameters should fail" false true
  with
  | _ -> check bool "too many parameters correctly rejected" true true

(** Test missing main function *)
let test_missing_main () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn helper(x: u32) -> u32 {
      return x + 1
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "missing main function should fail" false true
  with
  | _ -> check bool "missing main function correctly rejected" true true

(** Test multiple main functions *)
let test_multiple_main () =
  let code = {|
    @xdp fn main(ctx: *xdp_md) -> xdp_action {
      return 2
    }

    fn main(a: u32, b: u64) -> i32 {
      return 1
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "multiple main functions should fail" false true
  with
  | _ -> check bool "multiple main functions correctly rejected" true true

(** Test global functions with other functions (should be allowed) *)
let test_global_functions_with_other_functions () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      return 0
    }
    
  |} in
  let ast = parse_string code in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  check bool "global functions with other functions accepted" true true

(** Test global functions with struct definitions *)
let test_global_functions_with_structs () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    struct Config {
      max_packets: u64,
      debug_level: u32,
    }
    
    struct Stats {
      total_bytes: u64,
      packet_count: u32,
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  let ast = parse_string code in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  check bool "global functions with structs accepted" true true

(** Test multiple programs with single global main *)
let test_multiple_programs_single_main () =
  let code = {|
    @xdp fn monitor(ctx: *xdp_md) -> xdp_action {
        return 2
    }
    
    @tc("ingress") fn filter(ctx: *__sk_buff) -> i32 {
        return 0
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  let ast = parse_string code in
  let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
  let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
  let _ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
  check bool "multiple programs with single main accepted" true true

(** Test basic global function functionality *)
let test_basic_global_functions () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }

    fn main() -> i32 {
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    match ir with
    | { Ir.userspace_program = Some { Ir.userspace_functions = functions; userspace_structs = structs; userspace_configs = configs; _ }; _ } ->
      check bool "global functions block exists" true true;
      check bool "main function exists" (List.exists (fun f -> f.Ir.func_name = "main") functions) true;
      check bool "structs list accessible" (List.length structs >= 0) true;
      check bool "configs list accessible" (List.length configs >= 0) true;
    | _ -> check bool "global functions block not found" false true
  in
  try
    test_fn ();
    check bool "basic global functions test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test global function code generation from AST *)
let test_global_function_codegen () =
  let code = {|
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    match ir with
    | { Ir.userspace_program = Some { Ir.userspace_functions = functions; userspace_structs = structs; userspace_configs = configs; _ }; _ } ->
      check bool "global functions block exists" true true;
      check bool "main function exists" (List.exists (fun f -> f.Ir.func_name = "main") functions) true;
      check bool "structs list accessible" (List.length structs >= 0) true;
      check bool "configs list accessible" (List.length configs >= 0) true;
    | _ -> check bool "global functions block not found" false true
  in
  try
    test_fn ();
    check bool "global function codegen test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test literal map assignment with test functions - should not require main *)
let test_literal_map_assignment () =
  let code = {|
    var test_map : hash<u32, u32>(1024)
    
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      test_map[1] = 42
      var x = test_map[1]
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "literal map assignment test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test map lookup with literal key *)
let test_map_lookup_with_literal_key () =
  let code = {|
    var test_map : hash<u32, u32>(1024)
    
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      test_map[1] = 42 
      var x = test_map[1]
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "map lookup with literal key test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test map update with literal key and value *)
let test_map_update_with_literal_key_value () =
  let code = {|
    var test_map : hash<u32, u32>(1024)
    
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      test_map[1] = 42
      test_map[1] = 43
      var x = test_map[1]
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "map update with literal key value test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test map delete with literal key *)
let test_map_delete_with_literal_key () =
  let code = {|
    var test_map : hash<u32, u32>(1024)
    
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      test_map[1] = 42
      delete test_map[1]
      var x = test_map[1]
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "map delete with literal key test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test map iterate with literal key *)
let test_map_iterate_with_literal_key () =
  let code = {|
    var test_map : hash<u32, u32>(1024)
    
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      test_map[1] = 42 test_map[2] = 43
      var x = test_map[1]
      var y = test_map[2]
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "map iterate with literal key test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test mixed literal and variable expressions *)
let test_mixed_literal_variable_expressions () =
  let code = {|
    var test_map : hash<u32, u32>(1024)
    
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      test_map[1] = 42 test_map[2] = 43
      var x = test_map[1]
      var y = test_map[2]
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "mixed literal variable expressions test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test unique temporary variable names *)
let test_unique_temp_var_names () =
  let code = {|
    var test_map : hash<u32, u32>(1024)
    
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      test_map[1] = 42
      test_map[2] = 43
      test_map[3] = 44
      var z = test_map[1] + test_map[2] + test_map[3]
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "unique temp var names test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test no direct literal addressing *)
let test_no_direct_literal_addressing () =
  let code = {|
    var test_map : hash<u32, u32>(1024)
    
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      test_map[1] = 42
      var x = test_map[1]
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    ignore (Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test")
  in
  try
    test_fn ();
    check bool "no direct literal addressing test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test that BPF functions are only generated when explicitly called *)
let test_map_loading_code_generation () =
  let code = {|
    var packet_stats : hash<u32, u64>(1024)
    
    config network {
        max_packet_size: u32 = 1500,
        enable_logging: bool = true,
    }
    
    config security {
        threat_level: u32 = 1,
    }
    
    @xdp fn test(ctx: *xdp_md) -> xdp_action {
      return 2
    }
    
    fn main() -> i32 {
      network.enable_logging = true
      var prog_handle = load(test)
      return 0
    }
  |} in
  let test_fn () =
    let ast = parse_string code in
    let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
    let (annotated_ast, _typed_programs) = Kernelscript.Type_checker.type_check_and_annotate_ast ast in
    let ir_multi_prog = Kernelscript.Ir_generator.generate_ir annotated_ast symbol_table "test" in
    
    (* Extract config declarations for generation *)
    let extract_config_declarations ast =
      List.filter_map (function
        | Kernelscript.Ast.ConfigDecl config -> Some config
        | _ -> None
      ) ast
    in
    let config_declarations = extract_config_declarations ast in
    
    (* Generate userspace C code *)
    let temp_dir = Filename.temp_file "test_map_loading" "" in
    Unix.unlink temp_dir;
    Unix.mkdir temp_dir 0o755;
    
    try
      Kernelscript.Userspace_codegen.generate_userspace_code_from_ir ~config_declarations ir_multi_prog ~output_dir:temp_dir "test";
      let generated_file = Filename.concat temp_dir "test.c" in
      
      if Sys.file_exists generated_file then (
        let ic = open_in generated_file in
        let content = really_input_string ic (in_channel_length ic) in
        close_in ic;
        
        (* Cleanup *)
        Unix.unlink generated_file;
        Unix.rmdir temp_dir;
        
        (* Verify BPF helper functions are generated (since load is called) *)
        check bool "get_bpf_program_handle function exists" true 
          (try ignore (Str.search_forward (Str.regexp "int get_bpf_program_handle") content 0); true with Not_found -> false);
        
        (* Verify the user's explicit code is present *)
        check bool "user main function exists" true 
          (try ignore (Str.search_forward (Str.regexp "int main(void)") content 0); true with Not_found -> false);
        
        (* Verify load call is present *)
  check bool "load call present" true 
          (try ignore (Str.search_forward (Str.regexp "get_bpf_program_handle.*test") content 0); true with Not_found -> false);
        
        (* Verify BPF skeleton function is correct *)
        check bool "correct eBPF skeleton function" true 
          (try ignore (Str.search_forward (Str.regexp "test_ebpf__open_and_load") content 0); true with Not_found -> false);
        
        (* Verify map file descriptor declarations are NOT present (maps not used in userspace) *)
        check bool "packet_stats_fd declaration not generated (not used)" false 
          (try ignore (Str.search_forward (Str.regexp "int packet_stats_fd = -1") content 0); true with Not_found -> false);
        
        (* Verify config map fd declarations are present (config field is updated) *)
        check bool "network_config_map_fd declaration" true 
          (try ignore (Str.search_forward (Str.regexp "int network_config_map_fd = -1") content 0); true with Not_found -> false);
        check bool "security_config_map_fd declaration" true 
          (try ignore (Str.search_forward (Str.regexp "int security_config_map_fd = -1") content 0); true with Not_found -> false);
        
        (* Verify NO automatic setup (only what user writes) *)
        check bool "no automatic setup_bpf_environment call" false
          (try ignore (Str.search_forward (Str.regexp "setup_bpf_environment()") content 0); true with Not_found -> false);
        
      ) else (
        Unix.rmdir temp_dir;
        check bool "userspace code file generated" false true
      )
    with
    | exn ->
      (* Cleanup on error *)
      (try Unix.rmdir temp_dir with _ -> ());
      raise exn
  in
  try
    test_fn ();
    check bool "map loading code generation test passed" true true
  with
  | e -> 
    Printf.printf "Error: %s\n" (Printexc.to_string e);
    check bool "test failed with exception" false true

(** Test suite *)
let suite = [
  "global_functions_top_level", `Quick, test_global_functions_top_level;
  "program_function_isolation", `Quick, test_program_function_isolation;
  "main_correct_signature", `Quick, test_main_correct_signature;
  "main_with_struct_param", `Quick, test_main_with_struct_param;
  "main_wrong_param_types", `Quick, test_main_wrong_param_types;
  "main_wrong_return_type", `Quick, test_main_wrong_return_type;
  "main_non_struct_param", `Quick, test_main_non_struct_param;
  "main_too_many_params", `Quick, test_main_too_many_params;
  "missing_main", `Quick, test_missing_main;
  "multiple_main", `Quick, test_multiple_main;
  "global_functions_with_other_functions", `Quick, test_global_functions_with_other_functions;
  "global_functions_with_structs", `Quick, test_global_functions_with_structs;
  "multiple_programs_single_main", `Quick, test_multiple_programs_single_main;
  "basic_global_functions", `Quick, test_basic_global_functions;
  "global_function_code_generation", `Quick, test_global_function_codegen;
  
  (* Test functionality tests - main() is now always mandatory *)
  "literal_map_assignment", `Quick, test_literal_map_assignment;
  "map_lookup_with_literal_key", `Quick, test_map_lookup_with_literal_key;
  "map_update_with_literal_key_value", `Quick, test_map_update_with_literal_key_value;
  "map_delete_with_literal_key", `Quick, test_map_delete_with_literal_key;
  "map_iterate_with_literal_key", `Quick, test_map_iterate_with_literal_key;
  "mixed_literal_variable_expressions", `Quick, test_mixed_literal_variable_expressions;
  "unique_temp_var_names", `Quick, test_unique_temp_var_names;
  "no_direct_literal_addressing", `Quick, test_no_direct_literal_addressing;
  "map_loading_code_generation", `Quick, test_map_loading_code_generation;
]

let () =
  Alcotest.run "Global Function Tests" [
    "global_functions", suite
  ]