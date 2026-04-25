open Alcotest
open Kernelscript.Ast
open Kernelscript.Ir
open Kernelscript.Userspace_codegen

let contains_substr str substr =
  try
    let _ = Str.search_forward (Str.regexp_string substr) str 0 in
    true
  with Not_found -> false

let count_substr str substr =
  let regexp = Str.regexp_string substr in
  let rec loop start count =
    try
      let index = Str.search_forward regexp str start in
      loop (index + String.length substr) (count + 1)
    with Not_found -> count
  in
  loop 0 0

let test_pos = { line = 1; column = 1; filename = "test.ks" }

let int32_value value =
  make_ir_value (IRLiteral (IntLit (Signed64 value, None))) IRI32 test_pos

let uint32_value value =
  make_ir_value (IRLiteral (IntLit (Signed64 value, None))) IRU32 test_pos

let uint64_value value =
  make_ir_value (IRLiteral (IntLit (Signed64 value, None))) IRU64 test_pos

let bool_value value =
  make_ir_value (IRLiteral (BoolLit value)) IRBool test_pos

let perf_counter_value name raw_value =
  make_ir_value
    (IREnumConstant ("perf_counter", name, Signed64 raw_value))
    (IREnum ("perf_counter", []))
    test_pos

let perf_attr_expr ~pid ~cpu =
  make_ir_expr
    (IRStructLiteral ("perf_event_attr", [
      ("counter", perf_counter_value "branch_misses" 5L);
      ("pid", int32_value pid);
      ("cpu", int32_value cpu);
      ("period", uint64_value 1000000L);
      ("wakeup", uint32_value 1L);
      ("inherit", bool_value false);
      ("exclude_kernel", bool_value false);
      ("exclude_user", bool_value false);
    ]))
    (IRStruct ("perf_event_attr", []))
    test_pos

let make_generated_code instructions =
  let entry_block = make_ir_basic_block "entry" instructions 0 in
  let main_func = make_ir_function "main" [] (Some IRI32) [entry_block] ~is_main:true test_pos in
  let userspace_prog =
    make_ir_userspace_program
      [main_func]
      []
      (make_ir_coordinator_logic [] [] [] (make_ir_config_management [] [] []))
      test_pos
  in
  let ir_multi_prog = make_ir_multi_program "test" ~userspace_program:userspace_prog test_pos in
  generate_complete_userspace_program_from_ir userspace_prog [] ir_multi_prog "test.ks"

let test_perf_event_codegen_enforces_pid_cpu_rules () =
  let prog_handle = make_ir_value (IRVariable "prog") IRI32 test_pos in
  let attr_value = make_ir_value (IRVariable "attr") (IRStruct ("perf_event_attr", [])) test_pos in
  let attr_decl =
    make_ir_instruction
      (IRVariableDecl (attr_value, IRStruct ("perf_event_attr", []), Some (perf_attr_expr ~pid:(-1L) ~cpu:(-1L))))
      test_pos
  in
  let attach_call =
    make_ir_instruction
      (IRCall (DirectCall "attach", [prog_handle; attr_value], None))
      test_pos
  in
  let generated_code = make_generated_code [attr_decl; attach_call] in

  check bool "preserve raw cpu value" true
    (contains_substr generated_code "int cpu = ks_attr.cpu;");
  check bool "reject invalid pid below -1" true
    (contains_substr generated_code "if (pid < -1)");
  check bool "reject invalid cpu below -1" true
    (contains_substr generated_code "if (cpu < -1)");
  check bool "reject system-wide attach without explicit cpu" true
    (contains_substr generated_code "if (pid == -1 && cpu == -1)");
  check bool "remove old cpu normalization" false
    (contains_substr generated_code "int cpu = ks_attr.cpu >= 0 ? ks_attr.cpu : 0;");
  check bool "perf detach disables event" true
    (contains_substr generated_code "PERF_EVENT_IOC_DISABLE");
  check bool "perf detach closes event fd" true
    (contains_substr generated_code "close(entry->perf_fd);")

let test_standard_attach_uses_libbpf_error_checks () =
  let prog_handle = make_ir_value (IRVariable "prog") IRI32 test_pos in
  let target = make_ir_value (IRLiteral (StringLit "eth0")) (IRStr 16) test_pos in
  let flags = uint32_value 0L in
  let attach_call =
    make_ir_instruction
      (IRCall (DirectCall "attach", [prog_handle; target; flags], None))
      test_pos
  in
  let generated_code = make_generated_code [attach_call] in

  check int "standard attach branches use libbpf_get_error" 4
    (count_substr generated_code "libbpf_get_error(link)");
  check bool "old null-link checks removed" false
    (contains_substr generated_code "if (!link)");
  check bool "kprobe reports libbpf error string" true
    (contains_substr generated_code "Failed to attach kprobe to function '%s': %s");
  check bool "tracepoint reports libbpf error string" true
    (contains_substr generated_code "Failed to attach tracepoint to '%s:%s': %s");
  check bool "tc reports libbpf error string" true
    (contains_substr generated_code "Failed to attach TC program to interface '%s': %s")

let tests = [
  test_case "perf_event_codegen_enforces_pid_cpu_rules" `Quick test_perf_event_codegen_enforces_pid_cpu_rules;
  test_case "standard_attach_uses_libbpf_error_checks" `Quick test_standard_attach_uses_libbpf_error_checks;
]

let () = run "Perf Event Attach Tests" [
  ("perf_event_attach", tests);
]