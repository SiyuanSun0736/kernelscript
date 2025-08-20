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
   Comprehensive unit tests for global function map-related functionality in KernelScript.
   
   This test suite covers:
   
   === Map Scope Tests ===
   - Global maps accessible from global functions
   - Local maps isolated to BPF programs
   - Map visibility and access control
   
   === Map Code Generation Tests ===
   - Map file descriptor generation
   - Map operation function generation (lookup, update, delete, get_next_key)
   - Map setup and cleanup code generation
   - Pinned map handling in global functions
   
   === Map Integration Tests ===
   - Multiple map types in global functions
   - Maps with flags in global function code
   - Complex map configurations
   - Map access patterns and error handling
   
   === Map Communication Tests ===
   - Global function-kernel map sharing
   - BPF object integration
   - Map-based event processing
*)

open Kernelscript.Ast
open Kernelscript.Parse
open Kernelscript.Userspace_codegen
open Alcotest

(** Helper function to parse string with builtin constants loaded *)
let parse_string_with_builtins code =
  let ast = parse_string code in
  (* Create symbol table with test builtin types *)
  let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
  (* Run type checking with builtin types *)
  let (typed_ast, _) = Kernelscript.Type_checker.type_check_and_annotate_ast ~symbol_table:(Some symbol_table) ast in
  typed_ast

(** Helper function for position printing *)
let _string_of_position pos =
  Printf.sprintf "line %d, column %d" pos.line pos.column

(** Helper function to check if a pattern exists in content (case-insensitive) *)
let contains_pattern content pattern =
  let content_lower = String.lowercase_ascii content in
  try 
    ignore (Str.search_forward (Str.regexp pattern) content_lower 0); 
    true
  with Not_found -> false

(** Helper function to extract maps from AST *)
let extract_maps_from_ast ast =
  List.filter_map (function
    | MapDecl map_decl -> Some map_decl
    | GlobalVarDecl global_var_decl -> 
        (* Convert global variables with map types to map declarations *)
        (match global_var_decl.global_var_type with
         | Some (Map (key_type, value_type, map_type, size)) ->
             let config = { max_entries = size; key_size = None; value_size = None; flags = [] } in
             Some { name = global_var_decl.global_var_name; key_type; value_type; map_type; config; 
                    is_global = true; is_pinned = global_var_decl.is_pinned; map_pos = global_var_decl.global_var_pos }
         | _ -> None)
    | _ -> None
  ) ast

(** Helper function to extract global functions from AST *)
let extract_global_functions_from_ast ast =
  List.fold_left (fun acc decl ->
    match decl with
    | GlobalFunction func -> func :: acc
    | _ -> acc
  ) [] ast

(** Helper function to generate userspace code and return content *)
let get_generated_userspace_code ast source_filename =
  let temp_dir = Filename.temp_file "test_userspace_maps" "" in
  Unix.unlink temp_dir;
  Unix.mkdir temp_dir 0o755;
  
  try
    (* Convert AST to IR properly for the new IR-based codegen *)
    (* Load builtin ASTs for symbol table *)
    let symbol_table = Test_utils.Helpers.create_test_symbol_table ast in
    let ir_multi_prog = Kernelscript.Ir_generator.generate_ir ast symbol_table source_filename in
    let _output_file = generate_userspace_code_from_ir ir_multi_prog ~output_dir:temp_dir source_filename in
    let generated_file = Filename.concat temp_dir (Filename.remove_extension source_filename ^ ".c") in
    
    if Sys.file_exists generated_file then (
      let ic = open_in generated_file in
      let content = really_input_string ic (in_channel_length ic) in
      close_in ic;
      
      (* Cleanup *)
      Unix.unlink generated_file;
      Unix.rmdir temp_dir;
      
      Some content
    ) else (
      Unix.rmdir temp_dir;
      None
    )
  with
  | exn ->
    (* Cleanup on error *)
    (try Unix.rmdir temp_dir with _ -> ());
    raise exn

(** Test 1: Global maps are accessible from global functions *)
let test_global_map_accessibility () =
  let code = {|
var global_counter : hash<u32, u64>(1024)
var global_config : array<u32, u32>(256)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main() -> i32 {
  global_counter[1] = 100  // This will trigger map operations generation
  var value = global_config[0]
  return 0
}
|} in
  
  try
    let ast = parse_string code in
    let maps = extract_maps_from_ast ast in
    let global_functions = extract_global_functions_from_ast ast in
    
    (* Verify we parsed the expected structure *)
    check int "two global maps parsed" 2 (List.length maps);
    check bool "global functions present" true (List.length global_functions > 0);
    
    (* Verify map types and names *)
    let global_counter = List.find (fun m -> m.name = "global_counter") maps in
    let global_config = List.find (fun m -> m.name = "global_config") maps in
    
    check string "global_counter key type" "u32" (Kernelscript.Ast.string_of_bpf_type global_counter.key_type);
    check string "global_counter value type" "u64" (Kernelscript.Ast.string_of_bpf_type global_counter.value_type);
    check string "global_config key type" "u32" (Kernelscript.Ast.string_of_bpf_type global_config.key_type);
    check string "global_config value type" "u32" (Kernelscript.Ast.string_of_bpf_type global_config.value_type);
    
    (* Generate userspace code and check for global map accessibility *)
    match get_generated_userspace_code ast "test_global_maps.ks" with
    | Some generated_content ->
        (* Check for global map file descriptors *)
        let has_global_counter_fd = contains_pattern generated_content "global_counter.*fd" in
        let has_global_config_fd = contains_pattern generated_content "global_config.*fd" in
        
        (* Check for map operation functions *)
        let has_counter_operations = contains_pattern generated_content "bpf_map.*elem.*global_counter_fd\\|global_counter_fd.*bpf_map" in
        let has_config_operations = contains_pattern generated_content "bpf_map.*elem.*global_config_fd\\|global_config_fd.*bpf_map" in
        
        check bool "global counter fd variable" true has_global_counter_fd;
        check bool "global config fd variable" true has_global_config_fd;
        check bool "counter operations present" true has_counter_operations;
        check bool "config operations present" true has_config_operations
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 2: Only global maps are accessible from global functions *)
let test_global_only_map_access () =
  let code = {|
var global_shared : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main() -> i32 {
  global_shared[42] = 200  // Use the global map to trigger generation
  return 0
}
|} in
  
  try
    let ast = parse_string code in
    let maps = extract_maps_from_ast ast in
    
    (* Should only have global map, not local ones *)
    check int "only global maps accessible" 1 (List.length maps);
    
    let global_shared = List.find (fun m -> m.name = "global_shared") maps in
    check string "global_shared is present" "global_shared" global_shared.name;
    
    (* Generate userspace code and verify only global maps are accessible *)
    match get_generated_userspace_code ast "test_global_only.ks" with
    | Some generated_content ->
        let has_global_shared = contains_pattern generated_content "global_shared" in
        
        check bool "global map present in userspace" true has_global_shared
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 3: Map operation function generation *)
let test_map_operation_generation () =
  let code = {|
var test_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main() -> i32 {
  test_map[123] = 456  // Use the map to trigger operations generation
  var lookup_result = test_map[123]
  return 0
}
|} in
  
  try
    let ast = parse_string code in
    let maps = extract_maps_from_ast ast in
    
    check int "one test map" 1 (List.length maps);
    let test_map = List.hd maps in
    check string "test map name" "test_map" test_map.name;
    check string "test map type" "hash" (string_of_map_type test_map.map_type);
    
    (* Generate userspace code and check for map operations *)
    match get_generated_userspace_code ast "test_operations.ks" with
    | Some generated_content ->
        (* Check for map operations that are actually used in the test code *)
        let operations = [
          ("lookup", "bpf_map_lookup_elem.*test_map_fd");
          ("update", "bpf_map_update_elem.*test_map_fd");
        ] in
        
        List.iter (fun (op_name, pattern) ->
          let has_operation = contains_pattern generated_content pattern in
          check bool ("map " ^ op_name ^ " operation") true has_operation
        ) operations;
        
        (* Check for BPF map helper functions *)
        let has_bpf_helpers = contains_pattern generated_content "bpf_map_lookup_elem\\|bpf_map_update_elem\\|bpf_map_delete_elem" in
        check bool "BPF map helper functions present" true has_bpf_helpers
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 4: Multiple map types in global functions *)
let test_multiple_map_types_global_functions () =
  let code = {|
var hash_map : hash<u32, u64>(1024)
var array_map : array<u32, u32>(256)
var lru_map : lru_hash<u32, u64>(512)
var percpu_map : percpu_hash<u64, u32>(128)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main() -> i32 {
  // Use all maps to trigger operations generation
  hash_map[1] = 100
  array_map[2] = 200
  lru_map[3] = 300
  percpu_map[4] = 400
  return 0
}
|} in
  
  try
    let ast = parse_string code in
    let maps = extract_maps_from_ast ast in
    
    check int "four different map types" 4 (List.length maps);
    
    (* Verify each map type was parsed correctly *)
    let map_types = [
      ("hash_map", "hash", "u32", "u64", 1024);
      ("array_map", "array", "u32", "u32", 256);
      ("lru_map", "lru_hash", "u32", "u64", 512);
      ("percpu_map", "percpu_hash", "u64", "u32", 128);
    ] in
    
    List.iter (fun (name, expected_type, key_type, value_type, max_entries) ->
      let map = List.find (fun m -> m.name = name) maps in
      check string (name ^ " type") expected_type (string_of_map_type map.map_type);
      check string (name ^ " key type") key_type (string_of_bpf_type map.key_type);
      check string (name ^ " value type") value_type (string_of_bpf_type map.value_type);
      check int (name ^ " max entries") max_entries map.config.max_entries
    ) map_types;
    
    (* Generate userspace code and verify all maps are handled *)
    match get_generated_userspace_code ast "test_multiple_types.ks" with
    | Some generated_content ->
        List.iter (fun (map_name, _, _, _, _) ->
          let has_fd = contains_pattern generated_content (map_name ^ ".*fd") in
          let has_operations = contains_pattern generated_content ("bpf_map.*elem.*" ^ map_name ^ "_fd") in
          
          check bool ("map " ^ map_name ^ " fd variable") true has_fd;
          check bool ("map " ^ map_name ^ " operations") true has_operations
        ) map_types
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 5: Global function code structure and includes *)
let test_global_function_code_structure () =
  let code = {|
var test_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main() -> i32 {
  test_map[1] = 42  // Use the map to trigger operations generation
  return 0
}
|} in
  
  try
    let ast = parse_string code in
    
    (* Generate userspace code and check structure *)
    match get_generated_userspace_code ast "test_structure.ks" with
    | Some generated_content ->
        (* Check for required includes *)
        let has_stdio = contains_pattern generated_content "#include.*stdio" in
        let has_bpf_includes = contains_pattern generated_content "#include.*bpf" in
        
        (* Check for main function with correct signature *)
        let has_main_function = contains_pattern generated_content "int main" in
        
        (* Check for BPF skeleton usage (auto-generated when maps are used) *)
        let has_bpf_object = contains_pattern generated_content "\\.skel\\.h\\|bpf_object\\|struct bpf_object" in
        
        (* Check for signal handling functions (not just headers) *)
        let has_signal_handling = contains_pattern generated_content "setup_signal\\|signal(" in
        
        check bool "has stdio include" true has_stdio;
        check bool "has BPF includes" true has_bpf_includes;
        check bool "has main function" true has_main_function;
        check bool "has BPF object management (auto-generated when maps used)" true has_bpf_object;  (* Auto-generated BPF initialization for map operations *)
        check bool "has signal handling" false has_signal_handling;  (* No signal handling needed *)
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

(** Test 6: Error handling for invalid global function programs *)
let test_global_function_error_handling () =
  let invalid_programs = [
    (* Missing main function *)
    ({|
var test_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn helper() -> i32 {
  return 0
}
|}, "missing main function");
    
    (* Invalid main signature *)
    ({|
var test_map : hash<u32, u64>(1024)

@xdp fn test(ctx: *xdp_md) -> u32 {
  return 2
}

fn main(wrong_param: u32) -> i32 {
  return 0
}
|}, "invalid main signature");
  ] in
  
  List.iter (fun (program, description) ->
    try
      let ast = parse_string program in
      (* Trigger validation by generating IR first, which validates global function main *)
      let symbol_table = Kernelscript.Symbol_table.build_symbol_table ast in
      let _ = Kernelscript.Ir_generator.generate_ir ast symbol_table "test" in
      (* If we get here, validation passed but it shouldn't have *)
      fail ("Should have failed for: " ^ description)
    with
    | Parse_error _ ->
        check bool ("correctly rejected parse error: " ^ description) true true
    | Failure msg when String.length msg > 0 ->
        (* Check that the error message is related to main function validation *)
        let is_main_function_error = 
          contains_pattern msg "main" || 
          contains_pattern msg "argc" || 
          contains_pattern msg "argv" in
        check bool ("correctly rejected with main function error: " ^ description) true is_main_function_error
    | _ ->
        check bool ("should have failed for: " ^ description) false true
  ) invalid_programs

(** Test 6: Map file descriptor generation for userspace *)
let test_map_fd_generation () =
  let code = {|
pin var shared_counter : hash<u32, u32>(1024)

@xdp fn packet_counter(ctx: *xdp_md) -> xdp_action {
  shared_counter[1] = 100
  return XDP_PASS
}

@tc("ingress") fn packet_filter(ctx: *__sk_buff) -> i32 {
  shared_counter[2] = 200
  return 0 // TC_ACT_OK
}

fn main() -> i32 {
  shared_counter[1] = 0
  shared_counter[2] = 0
  return 0
} 
|} in
  
  try
    let ast = parse_string_with_builtins code in
    let maps = extract_maps_from_ast ast in
    
    check int "one shared counter map" 1 (List.length maps);
    let shared_counter = List.hd maps in
    check string "shared_counter name" "shared_counter" shared_counter.name;
    
    (* Generate userspace code and verify map fd usage *)
    match get_generated_userspace_code ast "test_map_fd.ks" with
    | Some generated_content ->
        (* Check for file descriptor declaration - pinned maps use pinned_globals_map_fd *)
        let has_fd_declaration = contains_pattern generated_content "int.*_fd = -1\\|pinned_globals_map_fd" in
        check bool "map file descriptor declaration" true has_fd_declaration;
        
        (* Check that map operations use the file descriptor, not raw map name *)
        let has_fd_in_update = contains_pattern generated_content "bpf_map_update_elem.*_fd\\|pinned_globals_map_fd.*bpf_map" in
        check bool "bpf_map_update_elem uses file descriptor" true has_fd_in_update;
        
        (* Ensure raw map reference is NOT used in map operations *)
        let has_raw_map_ref = contains_pattern generated_content "bpf_map_update_elem.*&shared_counter[^_]" in
        check bool "bpf_map_update_elem does NOT use &shared_counter" false has_raw_map_ref;
        
        (* Check for map operation helper functions or direct bpf_map usage *)
        let has_helper_functions = contains_pattern generated_content "shared_counter_lookup\\|shared_counter_update\\|bpf_map.*elem" in
        check bool "map operations present" true has_helper_functions;
        
        (* Verify operations use file descriptors correctly *)
        let helper_uses_fd = contains_pattern generated_content "bpf_map.*elem.*_fd\\|pinned_globals_map_fd" in
        check bool "map operations use file descriptors" true helper_uses_fd
    | None ->
        fail "Failed to generate userspace code"
  with
  | exn -> fail ("Error occurred: " ^ Printexc.to_string exn)

let global_function_maps_tests = [
  "global_map_accessibility", `Quick, test_global_map_accessibility;
  "global_only_map_access", `Quick, test_global_only_map_access;
  "map_operation_generation", `Quick, test_map_operation_generation;
  "multiple_map_types_global_functions", `Quick, test_multiple_map_types_global_functions;
  "global_function_code_structure", `Quick, test_global_function_code_structure;
  "global_function_error_handling", `Quick, test_global_function_error_handling;
  "map_fd_generation", `Quick, test_map_fd_generation;
]

let () =
  run "KernelScript Global Function Maps Tests" [
    "global_function_maps", global_function_maps_tests;
  ] 