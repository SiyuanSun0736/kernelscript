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

(** Loop analysis module for detecting bounded vs unbounded loops *)

open Ast

type loop_bound_info = 
  | Bounded of int * int  (* start, end - compile-time constants *)
  | Unbounded             (* runtime-determined bounds *)

type loop_analysis = {
  is_bounded: bool;
  bound_info: loop_bound_info;
  estimated_iterations: int option;
}

(** Constant environment for tracking variable assignments *)
type const_env = (string * Ast.integer_value) list

(** Check if an expression is a compile-time constant given a constant environment *)
let rec is_compile_time_constant_with_env const_env expr =
  match expr.expr_desc with
  | Literal (IntLit _) -> true
  | Identifier name -> 
      (* Check if this identifier is bound to a constant in our environment *)
      List.mem_assoc name const_env
  | BinaryOp (left, op, right) ->
      (* Only simple arithmetic on constants *)
      (match op with
       | Add | Sub | Mul | Div | Mod -> 
           is_compile_time_constant_with_env const_env left && 
           is_compile_time_constant_with_env const_env right
       | _ -> false)
  | UnaryOp (Neg, expr) -> is_compile_time_constant_with_env const_env expr
  | _ -> false

(** Extract integer value from compile-time constant expression *)
let rec evaluate_constant_expr_with_env const_env expr =
  match expr.expr_desc with
  | Literal (IntLit (i, _)) -> Some i
  | Identifier name ->
      (* Look up the identifier in our constant environment *)
      (try Some (List.assoc name const_env) with Not_found -> None)
  | BinaryOp (left, op, right) ->
      (match evaluate_constant_expr_with_env const_env left, 
             evaluate_constant_expr_with_env const_env right with
       | Some l, Some r ->
           (match op with
            | Add -> Some (Ast.Signed64 (Int64.add (Ast.IntegerValue.to_int64 l) (Ast.IntegerValue.to_int64 r)))
            | Sub -> Some (Ast.Signed64 (Int64.sub (Ast.IntegerValue.to_int64 l) (Ast.IntegerValue.to_int64 r)))
            | Mul -> Some (Ast.Signed64 (Int64.mul (Ast.IntegerValue.to_int64 l) (Ast.IntegerValue.to_int64 r)))
            | Div when Ast.IntegerValue.compare_with_zero r <> 0 -> Some (Ast.Signed64 (Int64.div (Ast.IntegerValue.to_int64 l) (Ast.IntegerValue.to_int64 r)))
            | Mod when Ast.IntegerValue.compare_with_zero r <> 0 -> Some (Ast.Signed64 (Int64.rem (Ast.IntegerValue.to_int64 l) (Ast.IntegerValue.to_int64 r)))
            | _ -> None)
       | _ -> None)
  | UnaryOp (Neg, expr) ->
      (match evaluate_constant_expr_with_env const_env expr with
       | Some i -> Some (Ast.Signed64 (Int64.neg (Ast.IntegerValue.to_int64 i)))
       | None -> None)
  | _ -> None

(** Collect constants from preceding statements *)
let collect_constants_from_statements statements =
  let rec collect_constants acc = function
    | [] -> acc
    | stmt :: rest ->
        (match stmt.stmt_desc with
         | Declaration (name, _, expr_opt) ->
             (* Try to evaluate the initializer expression *)
             (match expr_opt with
              | Some expr ->
                  (match evaluate_constant_expr_with_env acc expr with
                   | Some value -> collect_constants ((name, value) :: acc) rest
                   | None -> collect_constants acc rest)
              | None -> collect_constants acc rest)
         | Assignment (name, expr) ->
             (* Handle variable reassignment *)
             (match evaluate_constant_expr_with_env acc expr with
              | Some value -> 
                  let acc' = List.remove_assoc name acc in
                  collect_constants ((name, value) :: acc') rest
              | None -> 
                  let acc' = List.remove_assoc name acc in
                  collect_constants acc' rest)
         | _ -> collect_constants acc rest)
  in
  collect_constants [] statements

(** Analyze a for loop to determine if it's bounded *)
let analyze_for_loop_with_context const_env start_expr end_expr =
  let start_const = is_compile_time_constant_with_env const_env start_expr in
  let end_const = is_compile_time_constant_with_env const_env end_expr in
  
  if start_const && end_const then
    match evaluate_constant_expr_with_env const_env start_expr, 
          evaluate_constant_expr_with_env const_env end_expr with
    | Some start_val, Some end_val ->
        let iterations = Int64.to_int (Int64.max 0L (Int64.sub (Ast.IntegerValue.to_int64 end_val) (Ast.IntegerValue.to_int64 start_val))) in
        {
          is_bounded = true;
          bound_info = Bounded (Int64.to_int (Ast.IntegerValue.to_int64 start_val), Int64.to_int (Ast.IntegerValue.to_int64 end_val));
          estimated_iterations = Some iterations;
        }
    | _ ->
        {
          is_bounded = false;
          bound_info = Unbounded;
          estimated_iterations = None;
        }
  else
    {
      is_bounded = false;
      bound_info = Unbounded;
      estimated_iterations = None;
    }

(** Legacy functions for backward compatibility *)
let is_compile_time_constant expr = is_compile_time_constant_with_env [] expr
let evaluate_constant_expr expr = evaluate_constant_expr_with_env [] expr

let analyze_for_loop start_expr end_expr = analyze_for_loop_with_context [] start_expr end_expr

(** Analyze a for-iter loop (always considered unbounded for now) *)
let analyze_for_iter_loop _iterable_expr =
  {
    is_bounded = false;
    bound_info = Unbounded;
    estimated_iterations = None;
  }

(** Check if a loop is small enough for unrolling *)
let should_unroll_loop analysis =
  match analysis.estimated_iterations with
  | Some iterations when iterations <= 4 -> true
  | _ -> false

(** Check if a loop should use bpf_loop() *)
let should_use_bpf_loop analysis =
  not analysis.is_bounded || 
  (match analysis.estimated_iterations with
   | Some iterations when iterations > 100 -> true  (* Large bounded loops *)
   | _ -> false)

(** Pretty printing for debugging *)
let string_of_bound_info = function
  | Bounded (start, end_) -> Printf.sprintf "Bounded(%d, %d)" start end_
  | Unbounded -> "Unbounded"

let string_of_loop_analysis analysis =
  Printf.sprintf "{ is_bounded: %b; bound_info: %s; estimated_iterations: %s }"
    analysis.is_bounded
    (string_of_bound_info analysis.bound_info)
    (match analysis.estimated_iterations with
     | Some i -> string_of_int i
     | None -> "None")

(** Get eBPF-specific loop generation strategy *)
type loop_strategy = 
  | SimpleLoop      (* Use simple C for loop *)
  | UnrolledLoop    (* Unroll the loop completely *)
  | BpfLoopHelper   (* Use bpf_loop() helper *)

let get_ebpf_loop_strategy analysis =
  if should_unroll_loop analysis then
    UnrolledLoop
  else if should_use_bpf_loop analysis then
    BpfLoopHelper
  else
    SimpleLoop

let string_of_loop_strategy = function
  | SimpleLoop -> "SimpleLoop"
  | UnrolledLoop -> "UnrolledLoop" 
  | BpfLoopHelper -> "BpfLoopHelper" 