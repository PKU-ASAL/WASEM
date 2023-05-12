(module
  (type (;0;) (func (param i32 i64) (result i32)))
  (type (;1;) (func (param i64) (result i32)))
  (type (;2;) (func (param i32 i32 i32) (result i32)))
  (type (;3;) (func (param i32)))
  (type (;4;) (func (param i32) (result i64)))
  (type (;5;) (func))
  (type (;6;) (func (param i32 i32) (result i32)))
  (type (;7;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;8;) (func (param i64 i32)))
  (type (;9;) (func (param i64 i64) (result i32)))
  (type (;10;) (func (param i32) (result i32)))
  (type (;11;) (func (param i32 i32 i32 i32 i32 i32 f32 i32 i32 i32 i32 f32 i32 i32)))
  (type (;12;) (func (param i32 i32 i32 i32 i32)))
  (type (;13;) (func (param i32 i32) (result f32)))
  (type (;14;) (func (param i32 i32 i32)))
  (type (;15;) (func (param i32 i64 i32 i64)))
  (type (;16;) (func (param i32 i64 i64) (result i32)))
  (type (;17;) (func (param i32 i32)))
  (type (;18;) (func (param i32 i64 i64 i32 i32)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "malloc" (func $malloc (type 1)))
  (import "env" "memcpy" (func $memcpy (type 2)))
  (import "env" "free" (func $free (type 3)))
  (import "env" "strlen" (func $strlen (type 4)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 1)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 5)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 6)))
  (import "env" "memset" (func $memset (type 2)))
  (import "env" "vsnprintf" (func $vsnprintf (type 7)))
  (import "env" "__stack_chk_fail" (func $__stack_chk_fail (type 5)))
  (import "env" "free_matrix" (func $free_matrix (type 8)))
  (import "env" "calloc" (func $calloc (type 9)))
  (import "env" "realloc" (func $realloc (type 0)))
  (import "env" "sgx_spin_lock" (func $sgx_spin_lock (type 10)))
  (import "env" "gemm_cpu" (func $gemm_cpu (type 11)))
  (import "env" "sgx_spin_unlock" (func $sgx_spin_unlock (type 10)))
  (import "env" "sgx_file_string_to_list" (func $sgx_file_string_to_list (type 10)))
  (import "env" "sgx_parse_network_cfg" (func $sgx_parse_network_cfg (type 10)))
  (import "env" "free_list" (func $free_list (type 3)))
  (import "env" "load_categorical_data_csv" (func $load_categorical_data_csv (type 12)))
  (import "env" "get_current_batch" (func $get_current_batch (type 4)))
  (import "env" "train_network" (func $train_network (type 13)))
  (import "env" "network_predict" (func $network_predict (type 6)))
  (import "env" "free_network" (func $free_network (type 3)))
  (import "env" "make_matrix" (func $make_matrix (type 14)))
  (func $__wasm_call_ctors (type 5))
  (func $sgx_ecall_train_network (type 10) (param i32) (result i32)
    (local i32 i32 i32 i32 i64)
    local.get 0
    i32.load
    local.set 1
    local.get 0
    i32.load offset=8
    local.set 2
    i32.const 2
    local.set 3
    block  ;; label = @1
      local.get 0
      i64.const 16
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      local.set 4
      block  ;; label = @2
        local.get 1
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        local.get 2
        i64.extend_i32_s
        local.tee 5
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          local.get 5
          call $malloc
          local.tee 4
          br_if 0 (;@3;)
          i32.const 3
          return
        end
        local.get 4
        local.get 1
        local.get 5
        i32.wrap_i64
        call $memcpy
        drop
      end
      local.get 4
      local.get 2
      local.get 0
      i32.load offset=12
      call $ecall_train_network
      block  ;; label = @2
        local.get 4
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        call $free
      end
      i32.const 0
      local.set 3
    end
    local.get 3)
  (func $ecall_train_network (type 14) (param i32 i32 i32)
    (local i32 i64 i64 f32 f32)
    global.get $__stack_pointer
    i32.const 160
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    i32.const 0
    local.get 2
    i32.store offset=1324
    i32.const 0
    local.get 2
    i64.extend_i32_s
    local.tee 4
    i64.const 4
    call $calloc
    i32.store offset=1328
    i32.const 0
    local.get 4
    i64.const 80
    call $calloc
    i32.store offset=1336
    i32.const 0
    local.get 4
    i64.const 4
    call $calloc
    i32.store offset=1344
    local.get 3
    i32.const 112
    i32.add
    local.get 0
    local.get 1
    i32.const 0
    i32.const 10
    call $load_categorical_data_csv
    local.get 3
    local.get 3
    i32.load offset=120
    local.tee 1
    i32.store offset=132
    i32.const 1249
    i32.const 0
    call $printf
    local.get 3
    local.get 3
    i64.load offset=120
    i64.const 32
    i64.rotl
    i64.store offset=96
    i32.const 1237
    local.get 3
    i32.const 96
    i32.add
    call $printf
    local.get 3
    local.get 3
    i64.load offset=132
    i64.const 32
    i64.rotl
    i64.store offset=80
    i32.const 1225
    local.get 3
    i32.const 80
    i32.add
    call $printf
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=1320
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          i32.const 0
          i32.load offset=1324
          local.tee 0
          i32.const 1
          i32.lt_s
          br_if 0 (;@3;)
          i64.const 0
          local.set 4
          i32.const 0
          local.set 2
          loop  ;; label = @4
            i32.const 0
            i32.load offset=1328
            local.get 2
            i32.add
            call $sgx_spin_lock
            drop
            local.get 2
            i32.const 4
            i32.add
            local.set 2
            local.get 4
            i64.const 1
            i64.add
            local.tee 4
            i32.const 0
            i32.load offset=1324
            local.tee 0
            i64.extend_i32_s
            i64.lt_s
            br_if 0 (;@4;)
          end
        end
        local.get 0
        call $ocall_spawn_threads
        drop
        i32.const 0
        i32.const 1
        call $ocall_start_measuring_training
        drop
        i32.const 0
        i32.load offset=1320
        call $get_current_batch
        local.set 4
        block  ;; label = @3
          block  ;; label = @4
            i32.const 0
            i32.load offset=1320
            local.tee 2
            i64.load32_s offset=68
            local.tee 5
            i64.eqz
            br_if 0 (;@4;)
            local.get 4
            local.get 5
            i64.ge_u
            br_if 1 (;@3;)
          end
          local.get 1
          f32.convert_i32_s
          local.set 6
          local.get 3
          i32.const 32
          i32.add
          i32.const 40
          i32.add
          local.set 0
          loop  ;; label = @4
            local.get 0
            local.get 3
            i32.const 112
            i32.add
            i32.const 40
            i32.add
            i32.load
            i32.store
            local.get 3
            i32.const 32
            i32.add
            i32.const 32
            i32.add
            local.get 3
            i32.const 112
            i32.add
            i32.const 32
            i32.add
            i64.load
            i64.store
            local.get 3
            i32.const 32
            i32.add
            i32.const 24
            i32.add
            local.get 3
            i32.const 112
            i32.add
            i32.const 24
            i32.add
            i64.load
            i64.store
            local.get 3
            i32.const 32
            i32.add
            i32.const 16
            i32.add
            local.get 3
            i32.const 112
            i32.add
            i32.const 16
            i32.add
            i64.load
            i64.store
            local.get 3
            i32.const 32
            i32.add
            i32.const 8
            i32.add
            local.get 3
            i32.const 112
            i32.add
            i32.const 8
            i32.add
            i64.load
            i64.store
            local.get 3
            local.get 3
            i64.load offset=112
            i64.store offset=32
            local.get 2
            local.get 3
            i32.const 32
            i32.add
            call $train_network
            local.tee 7
            f32.const -0x1p+0 (;=-1;)
            f32.eq
            br_if 3 (;@1;)
            i32.const 0
            i32.load offset=1320
            i32.load offset=8
            i64.load
            local.set 4
            local.get 3
            local.get 7
            f64.promote_f32
            f64.store offset=24
            local.get 3
            local.get 4
            f32.convert_i64_u
            local.get 6
            f32.div
            f64.promote_f32
            f64.store offset=16
            i32.const 1096
            local.get 3
            i32.const 16
            i32.add
            call $printf
            i32.const 0
            i32.load offset=1320
            call $get_current_batch
            local.set 4
            i32.const 0
            i32.load offset=1320
            local.tee 2
            i64.load32_s offset=68
            local.tee 5
            i64.eqz
            br_if 0 (;@4;)
            local.get 4
            local.get 5
            i64.lt_u
            br_if 0 (;@4;)
          end
        end
        i32.const 0
        local.set 2
        i32.const 0
        i32.const 1
        call $ocall_end_measuring_training
        drop
        i32.const 0
        i32.load offset=1320
        call $save_weights_network*_
        i32.const 1280
        i32.const 0
        call $printf
        i32.const 0
        i32.load offset=1320
        local.get 3
        i32.const 128
        i32.add
        i32.load
        i32.load
        call $network_predict
        local.set 0
        block  ;; label = @3
          local.get 3
          i32.load offset=136
          i32.const 1
          i32.lt_s
          br_if 0 (;@3;)
          i64.const 0
          local.set 4
          loop  ;; label = @4
            local.get 3
            i32.load offset=140
            i32.load
            local.get 2
            i32.add
            f32.load
            local.set 7
            local.get 3
            local.get 0
            local.get 2
            i32.add
            f32.load
            f64.promote_f32
            f64.store offset=8
            local.get 3
            local.get 7
            f64.promote_f32
            f64.store
            i32.const 1200
            local.get 3
            call $printf
            local.get 2
            i32.const 4
            i32.add
            local.set 2
            local.get 4
            i64.const 1
            i64.add
            local.tee 4
            local.get 3
            i64.load32_s offset=136
            i64.lt_s
            br_if 0 (;@4;)
          end
        end
        local.get 3
        i32.load offset=140
        local.set 2
        local.get 3
        i32.load offset=128
        local.set 0
        block  ;; label = @3
          block  ;; label = @4
            local.get 3
            i32.load offset=144
            br_if 0 (;@4;)
            local.get 3
            i64.load offset=132
            local.set 4
            local.get 3
            i64.load offset=120
            local.get 0
            call $free_matrix
            local.get 4
            local.get 2
            call $free_matrix
            br 1 (;@3;)
          end
          local.get 0
          call $free
          local.get 2
          call $free
        end
        i32.const 0
        i32.load offset=1320
        call $free_network
        br 1 (;@1;)
      end
      i32.const 1144
      i32.const 0
      call $printf
    end
    local.get 3
    i32.const 160
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_test_network (type 10) (param i32) (result i32)
    (local i32 i32 i32 i32 i64)
    local.get 0
    i32.load
    local.set 1
    local.get 0
    i32.load offset=8
    local.set 2
    i32.const 2
    local.set 3
    block  ;; label = @1
      local.get 0
      i64.const 16
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      local.set 4
      block  ;; label = @2
        local.get 1
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        local.get 2
        i64.extend_i32_s
        local.tee 5
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          local.get 5
          call $malloc
          local.tee 4
          br_if 0 (;@3;)
          i32.const 3
          return
        end
        local.get 4
        local.get 1
        local.get 5
        i32.wrap_i64
        call $memcpy
        drop
      end
      local.get 4
      local.get 2
      local.get 0
      i32.load offset=12
      call $ecall_test_network
      block  ;; label = @2
        local.get 4
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        call $free
      end
      i32.const 0
      local.set 3
    end
    local.get 3)
  (func $ecall_test_network (type 14) (param i32 i32 i32)
    (local i32 i64 i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    block  ;; label = @1
      i32.const 0
      i32.load offset=1320
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      local.get 2
      i32.store offset=1324
      i32.const 0
      local.get 2
      i64.extend_i32_s
      local.tee 4
      i64.const 4
      call $calloc
      local.tee 5
      i32.store offset=1328
      i32.const 0
      local.get 4
      i64.const 80
      call $calloc
      i32.store offset=1336
      i32.const 0
      local.get 4
      i64.const 4
      call $calloc
      i32.store offset=1344
      block  ;; label = @2
        local.get 2
        i32.const 1
        i32.lt_s
        br_if 0 (;@2;)
        local.get 5
        call $sgx_spin_lock
        drop
        i32.const 0
        i32.load offset=1324
        local.tee 2
        i32.const 2
        i32.lt_s
        br_if 0 (;@2;)
        i32.const 4
        local.set 5
        i64.const 1
        local.set 4
        loop  ;; label = @3
          i32.const 0
          i32.load offset=1328
          local.get 5
          i32.add
          call $sgx_spin_lock
          drop
          local.get 5
          i32.const 4
          i32.add
          local.set 5
          local.get 4
          i64.const 1
          i64.add
          local.tee 4
          i32.const 0
          i32.load offset=1324
          local.tee 2
          i64.extend_i32_s
          i64.lt_s
          br_if 0 (;@3;)
        end
      end
      local.get 2
      call $ocall_spawn_threads
      drop
      local.get 3
      local.get 0
      local.get 1
      i32.const 0
      i32.const 10
      call $load_categorical_data_csv
      block  ;; label = @2
        local.get 3
        i32.load offset=8
        i32.const 1
        i32.lt_s
        br_if 0 (;@2;)
        i64.const 0
        local.set 4
        i32.const 0
        local.set 5
        loop  ;; label = @3
          i32.const 0
          i32.load offset=1320
          local.get 3
          i32.load offset=16
          local.get 5
          i32.add
          i32.load
          call $network_predict
          drop
          local.get 5
          i32.const 4
          i32.add
          local.set 5
          local.get 4
          i64.const 1
          i64.add
          local.tee 4
          local.get 3
          i64.load32_s offset=8
          i64.lt_s
          br_if 0 (;@3;)
        end
      end
      local.get 3
      i32.load offset=16
      local.set 5
      local.get 3
      i32.load offset=28
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=32
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=20
          local.set 4
          local.get 3
          i64.load offset=8
          local.get 5
          call $free_matrix
          local.get 4
          local.get 2
          call $free_matrix
          br 1 (;@2;)
        end
        local.get 5
        call $free
        local.get 2
        call $free
      end
      i32.const 0
      i32.load offset=1320
      call $free_network
    end
    local.get 3
    i32.const 48
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_thread_enter_enclave_waiting (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 4
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load
      call $ecall_thread_enter_enclave_waiting
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_thread_enter_enclave_waiting (type 3) (param i32)
    (local i32 i32)
    local.get 0
    i64.extend_i32_s
    i32.wrap_i64
    local.tee 0
    i32.const 2
    i32.shl
    local.set 1
    local.get 0
    i32.const 56
    i32.mul
    local.set 2
    loop  ;; label = @1
      i32.const 0
      i32.load offset=1328
      local.get 1
      i32.add
      call $sgx_spin_lock
      drop
      i32.const 0
      i32.load offset=1336
      local.get 2
      i32.add
      local.tee 0
      i32.load
      local.get 0
      i32.load offset=4
      local.get 0
      i32.load offset=8
      local.get 0
      i32.load offset=12
      local.get 0
      i32.load offset=16
      local.get 0
      i32.load offset=20
      local.get 0
      f32.load offset=24
      local.get 0
      i32.load offset=28
      local.get 0
      i32.load offset=32
      local.get 0
      i32.load offset=36
      local.get 0
      i32.load offset=44
      local.get 0
      f32.load offset=40
      local.get 0
      i32.load offset=48
      local.get 0
      i32.load offset=52
      call $gemm_cpu
      i32.const 0
      i32.load offset=1344
      local.get 1
      i32.add
      i32.const 1
      i32.store
      i32.const 0
      i32.load offset=1328
      local.get 1
      i32.add
      call $sgx_spin_unlock
      drop
      i32.const 0
      i32.load offset=1344
      local.get 1
      i32.add
      local.set 0
      loop  ;; label = @2
        local.get 0
        i32.load
        i32.const 1
        i32.eq
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
    end)
  (func $sgx_ecall_build_network (type 10) (param i32) (result i32)
    (local i64 i32 i64 i32 i32 i32)
    local.get 0
    i64.load offset=24
    local.set 1
    local.get 0
    i32.load offset=16
    local.set 2
    local.get 0
    i64.load offset=8
    local.set 3
    local.get 0
    i32.load
    local.set 4
    i32.const 2
    local.set 5
    block  ;; label = @1
      local.get 0
      i64.const 32
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 4
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        local.get 3
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 2
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        local.get 1
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 6
      i32.const 0
      local.set 0
      block  ;; label = @2
        local.get 4
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 3
          call $malloc
          local.tee 0
          br_if 0 (;@3;)
          i32.const 3
          return
        end
        local.get 0
        local.get 4
        local.get 3
        i32.wrap_i64
        call $memcpy
        drop
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            call $malloc
            local.tee 6
            br_if 0 (;@4;)
            i32.const 0
            local.set 6
            i32.const 3
            local.set 5
            br 2 (;@2;)
          end
          local.get 6
          local.get 2
          local.get 1
          i32.wrap_i64
          call $memcpy
          drop
        end
        local.get 0
        local.get 3
        local.get 6
        local.get 1
        call $ecall_build_network
        i32.const 0
        local.set 5
      end
      block  ;; label = @2
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        call $free
      end
      local.get 6
      i32.eqz
      br_if 0 (;@1;)
      local.get 6
      call $free
    end
    local.get 5)
  (func $ecall_build_network (type 15) (param i32 i64 i32 i64)
    (local i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        br_if 0 (;@2;)
        i32.const 1175
        local.set 0
        br 1 (;@1;)
      end
      local.get 0
      call $sgx_file_string_to_list
      local.tee 4
      call $sgx_parse_network_cfg
      local.set 0
      local.get 4
      call $free_list
      block  ;; label = @2
        local.get 2
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 2
        call $load_weights_network*__char*_
      end
      i32.const 0
      local.get 0
      i32.store offset=1320
      i32.const 1128
      local.set 0
    end
    local.get 0
    i32.const 0
    call $printf)
  (func $ocall_print_string (type 10) (param i32) (result i32)
    (local i64 i64 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        br_if 0 (;@2;)
        i64.const 8
        local.set 1
        i64.const 0
        local.set 2
        br 1 (;@1;)
      end
      local.get 0
      call $strlen
      local.tee 1
      i64.const 9
      i64.add
      i64.const 8
      local.get 0
      local.get 1
      i64.const 1
      i64.add
      local.tee 2
      call $sgx_is_within_enclave
      select
      local.set 1
    end
    block  ;; label = @1
      local.get 1
      call $sgx_ocalloc
      local.tee 3
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 0
          local.get 2
          call $sgx_is_within_enclave
          br_if 0 (;@3;)
          call $sgx_ocfree
          i32.const 2
          return
        end
        local.get 3
        local.get 3
        i32.const 8
        i32.add
        local.tee 4
        i32.store
        local.get 4
        local.get 0
        local.get 2
        i32.wrap_i64
        call $memcpy
        drop
        br 1 (;@1;)
      end
      local.get 3
      i32.const 0
      i32.store
    end
    i32.const 0
    local.get 3
    call $sgx_ocall
    local.set 0
    call $sgx_ocfree
    local.get 0)
  (func $ocall_start_measuring_training (type 6) (param i32 i32) (result i32)
    (local i32)
    block  ;; label = @1
      i64.const 8
      call $sgx_ocalloc
      local.tee 2
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    local.get 2
    local.get 1
    i32.store offset=4
    local.get 2
    local.get 0
    i32.store
    i32.const 1
    local.get 2
    call $sgx_ocall
    local.set 2
    call $sgx_ocfree
    local.get 2)
  (func $ocall_end_measuring_training (type 6) (param i32 i32) (result i32)
    (local i32)
    block  ;; label = @1
      i64.const 8
      call $sgx_ocalloc
      local.tee 2
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    local.get 2
    local.get 1
    i32.store offset=4
    local.get 2
    local.get 0
    i32.store
    i32.const 2
    local.get 2
    call $sgx_ocall
    local.set 2
    call $sgx_ocfree
    local.get 2)
  (func $ocall_spawn_threads (type 10) (param i32) (result i32)
    (local i32)
    block  ;; label = @1
      i64.const 4
      call $sgx_ocalloc
      local.tee 1
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    local.get 1
    local.get 0
    i32.store
    i32.const 3
    local.get 1
    call $sgx_ocall
    local.set 1
    call $sgx_ocfree
    local.get 1)
  (func $ocall_push_weights (type 16) (param i32 i64 i64) (result i32)
    (local i64 i64 i32 i32)
    local.get 2
    local.get 1
    i64.mul
    local.set 3
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        br_if 0 (;@2;)
        i64.const 24
        local.set 4
        br 1 (;@1;)
      end
      local.get 3
      i64.const 24
      i64.add
      i64.const 24
      local.get 0
      local.get 3
      call $sgx_is_within_enclave
      select
      local.set 4
    end
    block  ;; label = @1
      local.get 4
      call $sgx_ocalloc
      local.tee 5
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 0
          local.get 3
          call $sgx_is_within_enclave
          br_if 0 (;@3;)
          call $sgx_ocfree
          i32.const 2
          return
        end
        local.get 5
        local.get 5
        i32.const 24
        i32.add
        local.tee 6
        i32.store
        local.get 6
        local.get 0
        local.get 3
        i32.wrap_i64
        call $memcpy
        drop
        br 1 (;@1;)
      end
      local.get 5
      i32.const 0
      i32.store
    end
    local.get 5
    local.get 2
    i64.store offset=16
    local.get 5
    local.get 1
    i64.store offset=8
    i32.const 4
    local.get 5
    call $sgx_ocall
    local.set 0
    call $sgx_ocfree
    local.get 0)
  (func $printf (type 17) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 8224
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=8220
    local.get 2
    i32.const 16
    i32.add
    i32.const 0
    i32.const 8192
    call $memset
    drop
    local.get 2
    local.get 1
    i32.store
    local.get 2
    i32.const 16
    i32.add
    i64.const 8192
    local.get 0
    local.get 2
    call $vsnprintf
    drop
    local.get 2
    i32.const 16
    i32.add
    call $ocall_print_string
    drop
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=8220
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 2
    i32.const 8224
    i32.add
    global.set $__stack_pointer)
  (func $free_data_data_ (type 3) (param i32)
    block  ;; label = @1
      local.get 0
      i32.load offset=32
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=8
      local.get 0
      i32.const 16
      i32.add
      i32.load
      call $free_matrix
      local.get 0
      i64.load offset=20
      local.get 0
      i32.const 28
      i32.add
      i32.load
      call $free_matrix
      return
    end
    local.get 0
    i32.const 16
    i32.add
    i32.load
    call $free
    local.get 0
    i32.const 28
    i32.add
    i32.load
    call $free)
  (func $transpose_matrix_float*__int__int_ (type 14) (param i32 i32 i32)
    (local i64 i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i32 i32 i32 i32)
    local.get 2
    local.get 1
    i32.mul
    i64.extend_i32_s
    local.tee 3
    i64.const 4
    call $calloc
    local.set 4
    block  ;; label = @1
      local.get 1
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      local.get 2
      i32.const 2
      i32.shl
      local.set 5
      local.get 1
      i32.const 3
      i32.shl
      local.set 6
      local.get 1
      i32.const 2
      i32.shl
      local.set 7
      local.get 2
      i64.extend_i32_u
      local.tee 8
      i64.const 4294967294
      i64.and
      local.set 9
      local.get 8
      i64.const 1
      i64.and
      local.set 10
      local.get 1
      i64.extend_i32_u
      local.set 11
      local.get 2
      i64.extend_i32_s
      local.set 12
      i64.const 0
      local.set 13
      local.get 2
      i32.const 1
      i32.lt_s
      local.set 14
      local.get 0
      local.set 15
      local.get 4
      local.set 16
      loop  ;; label = @2
        block  ;; label = @3
          local.get 14
          br_if 0 (;@3;)
          i64.const 0
          local.set 8
          block  ;; label = @4
            local.get 2
            i32.const 1
            i32.eq
            br_if 0 (;@4;)
            i64.const 0
            local.set 8
            local.get 15
            local.set 1
            local.get 16
            local.set 17
            loop  ;; label = @5
              local.get 17
              local.get 1
              f32.load
              f32.store
              local.get 17
              local.get 7
              i32.add
              local.get 1
              i32.const 4
              i32.add
              f32.load
              f32.store
              local.get 1
              i32.const 8
              i32.add
              local.set 1
              local.get 17
              local.get 6
              i32.add
              local.set 17
              local.get 9
              local.get 8
              i64.const 2
              i64.add
              local.tee 8
              i64.ne
              br_if 0 (;@5;)
            end
          end
          local.get 10
          i64.eqz
          br_if 0 (;@3;)
          local.get 4
          local.get 8
          local.get 11
          i64.mul
          local.get 13
          i64.add
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          local.get 0
          local.get 8
          local.get 13
          local.get 12
          i64.mul
          i64.add
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          f32.load
          f32.store
        end
        local.get 15
        local.get 5
        i32.add
        local.set 15
        local.get 16
        i32.const 4
        i32.add
        local.set 16
        local.get 13
        i64.const 1
        i64.add
        local.tee 13
        local.get 11
        i64.ne
        br_if 0 (;@2;)
      end
    end
    local.get 0
    local.get 4
    local.get 3
    i32.wrap_i64
    i32.const 2
    i32.shl
    call $memcpy
    drop
    local.get 4
    call $free)
  (func $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_ (type 18) (param i32 i64 i64 i32 i32)
    local.get 0
    local.get 3
    local.get 4
    i32.load
    i32.add
    local.get 2
    local.get 1
    i64.mul
    i32.wrap_i64
    local.tee 3
    call $memcpy
    drop
    local.get 4
    local.get 4
    i32.load
    local.get 3
    i32.add
    i32.store)
  (func $load_connected_weights_layer__char*__int*_ (type 14) (param i32 i32 i32)
    (local i32 i32 i32)
    local.get 0
    i32.load offset=432
    local.get 1
    local.get 2
    i32.load
    i32.add
    local.get 0
    i32.load offset=60
    local.tee 3
    i64.extend_i32_s
    i64.const 2
    i64.shl
    i32.wrap_i64
    local.tee 4
    call $memcpy
    drop
    local.get 2
    local.get 2
    i32.load
    local.get 4
    i32.add
    local.tee 5
    i32.store
    local.get 0
    i32.load offset=448
    local.get 1
    local.get 5
    i32.add
    local.get 3
    local.get 0
    i32.load offset=56
    i32.mul
    i32.const 2
    i32.shl
    local.tee 3
    call $memcpy
    drop
    local.get 2
    local.get 2
    i32.load
    local.get 3
    i32.add
    local.tee 3
    i32.store
    block  ;; label = @1
      local.get 0
      i32.load offset=36
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=348
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=440
      local.get 1
      local.get 3
      i32.add
      local.get 4
      call $memcpy
      drop
      local.get 2
      local.get 2
      i32.load
      local.get 4
      i32.add
      local.tee 3
      i32.store
      local.get 0
      i32.load offset=496
      local.get 1
      local.get 3
      i32.add
      local.get 4
      call $memcpy
      drop
      local.get 2
      local.get 2
      i32.load
      local.get 4
      i32.add
      local.tee 3
      i32.store
      local.get 0
      i32.load offset=500
      local.get 1
      local.get 3
      i32.add
      local.get 4
      call $memcpy
      drop
      local.get 2
      local.get 2
      i32.load
      local.get 4
      i32.add
      i32.store
    end)
  (func $load_convolutional_weights_layer__char*__int*_ (type 14) (param i32 i32 i32)
    (local i32 i32 i32 i32 i64 i32 i32 i32 i32 i64 i64 i64 i64 i64 i64)
    local.get 0
    i32.load offset=116
    local.set 3
    local.get 0
    i32.load offset=112
    local.set 4
    local.get 0
    i32.load offset=88
    local.set 5
    local.get 0
    i32.load offset=432
    local.get 1
    local.get 2
    i32.load
    i32.add
    local.get 0
    i32.load offset=104
    local.tee 6
    i64.extend_i32_s
    local.tee 7
    i64.const 2
    i64.shl
    i32.wrap_i64
    local.tee 8
    call $memcpy
    drop
    local.get 2
    local.get 2
    i32.load
    local.get 8
    i32.add
    local.tee 9
    i32.store
    local.get 6
    local.get 3
    local.get 3
    i32.mul
    local.tee 10
    local.get 5
    local.get 4
    i32.div_s
    i32.mul
    i32.mul
    local.set 3
    block  ;; label = @1
      local.get 0
      i32.load offset=36
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=348
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=440
      local.get 1
      local.get 9
      i32.add
      local.get 8
      call $memcpy
      drop
      local.get 2
      local.get 2
      i32.load
      local.get 8
      i32.add
      local.tee 9
      i32.store
      local.get 0
      i32.load offset=496
      local.get 1
      local.get 9
      i32.add
      local.get 8
      call $memcpy
      drop
      local.get 2
      local.get 2
      i32.load
      local.get 8
      i32.add
      local.tee 9
      i32.store
      local.get 0
      i32.load offset=500
      local.get 1
      local.get 9
      i32.add
      local.get 8
      call $memcpy
      drop
      local.get 2
      local.get 2
      i32.load
      local.get 8
      i32.add
      local.tee 9
      i32.store
    end
    local.get 0
    i32.load offset=448
    local.get 1
    local.get 9
    i32.add
    local.get 3
    i32.const 2
    i32.shl
    local.tee 1
    call $memcpy
    local.set 11
    local.get 2
    local.get 2
    i32.load
    local.get 1
    i32.add
    i32.store
    block  ;; label = @1
      local.get 0
      i32.load offset=52
      i32.eqz
      br_if 0 (;@1;)
      local.get 10
      local.get 5
      i32.mul
      local.tee 0
      local.get 6
      i32.mul
      i64.extend_i32_s
      local.tee 12
      i64.const 4
      call $calloc
      local.set 10
      block  ;; label = @2
        local.get 0
        i32.const 1
        i32.lt_s
        br_if 0 (;@2;)
        local.get 6
        i32.const 2
        i32.shl
        local.set 9
        local.get 6
        i64.extend_i32_u
        local.tee 13
        i64.const 4294967294
        i64.and
        local.set 14
        local.get 13
        i64.const 1
        i64.and
        local.set 15
        local.get 0
        i32.const 3
        i32.shl
        local.set 1
        local.get 0
        i32.const 2
        i32.shl
        local.set 8
        local.get 0
        i64.extend_i32_u
        local.set 16
        i64.const 0
        local.set 17
        local.get 6
        i32.const 1
        i32.lt_s
        local.set 4
        local.get 11
        local.set 3
        local.get 10
        local.set 5
        loop  ;; label = @3
          block  ;; label = @4
            local.get 4
            br_if 0 (;@4;)
            i64.const 0
            local.set 13
            block  ;; label = @5
              local.get 6
              i32.const 1
              i32.eq
              br_if 0 (;@5;)
              i64.const 0
              local.set 13
              local.get 3
              local.set 0
              local.get 5
              local.set 2
              loop  ;; label = @6
                local.get 2
                local.get 0
                f32.load
                f32.store
                local.get 2
                local.get 8
                i32.add
                local.get 0
                i32.const 4
                i32.add
                f32.load
                f32.store
                local.get 0
                i32.const 8
                i32.add
                local.set 0
                local.get 2
                local.get 1
                i32.add
                local.set 2
                local.get 14
                local.get 13
                i64.const 2
                i64.add
                local.tee 13
                i64.ne
                br_if 0 (;@6;)
              end
            end
            local.get 15
            i64.eqz
            br_if 0 (;@4;)
            local.get 10
            local.get 13
            local.get 16
            i64.mul
            local.get 17
            i64.add
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            local.get 11
            local.get 13
            local.get 17
            local.get 7
            i64.mul
            i64.add
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            f32.load
            f32.store
          end
          local.get 3
          local.get 9
          i32.add
          local.set 3
          local.get 5
          i32.const 4
          i32.add
          local.set 5
          local.get 17
          i64.const 1
          i64.add
          local.tee 17
          local.get 16
          i64.ne
          br_if 0 (;@3;)
        end
      end
      local.get 11
      local.get 10
      local.get 12
      i32.wrap_i64
      i32.const 2
      i32.shl
      call $memcpy
      drop
      local.get 10
      call $free
    end)
  (func $load_weights_network*__char*_ (type 17) (param i32 i32)
    (local i32 i64 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i64 i32 i64 i64 i64 i64 i64 i64)
    block  ;; label = @1
      local.get 0
      i32.load
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      i32.const 0
      local.set 2
      i64.const 0
      local.set 3
      loop  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=24
          local.get 3
          i32.wrap_i64
          i32.const 752
          i32.mul
          i32.add
          local.tee 4
          i32.load offset=340
          br_if 0 (;@3;)
          local.get 4
          i32.const 640
          i32.add
          i32.load
          local.set 5
          local.get 4
          i32.const 632
          i32.add
          i32.load
          local.set 6
          local.get 4
          i32.const 536
          i32.add
          i32.load
          local.set 7
          local.get 4
          i32.const 520
          i32.add
          i32.load
          local.set 8
          local.get 4
          i32.const 504
          i32.add
          i32.load
          local.set 9
          local.get 4
          i32.const 348
          i32.add
          i32.load
          local.set 10
          local.get 4
          i32.const 64
          i32.add
          i32.load
          local.set 11
          block  ;; label = @4
            block  ;; label = @5
              local.get 4
              i32.load
              br_table 0 (;@5;) 2 (;@3;) 1 (;@4;) 2 (;@3;)
            end
            local.get 4
            i32.const 144
            i32.add
            i32.load
            local.set 12
            local.get 4
            i32.const 140
            i32.add
            i32.load
            local.set 13
            local.get 4
            i32.const 116
            i32.add
            i32.load
            local.set 14
            local.get 4
            i32.const 80
            i32.add
            i32.load
            local.set 15
            local.get 9
            local.get 1
            local.get 2
            i32.add
            local.get 4
            i32.const 132
            i32.add
            i32.load
            local.tee 16
            i64.extend_i32_s
            local.tee 17
            i64.const 2
            i64.shl
            i32.wrap_i64
            local.tee 4
            call $memcpy
            drop
            local.get 16
            local.get 12
            local.get 12
            i32.mul
            local.tee 18
            i32.mul
            local.get 14
            local.get 13
            i32.div_s
            i32.mul
            local.set 12
            local.get 2
            local.get 4
            i32.add
            local.set 9
            block  ;; label = @5
              local.get 11
              i32.eqz
              br_if 0 (;@5;)
              local.get 10
              br_if 0 (;@5;)
              local.get 8
              local.get 1
              local.get 9
              i32.add
              local.get 4
              call $memcpy
              drop
              local.get 6
              local.get 1
              local.get 9
              local.get 4
              i32.add
              local.tee 9
              i32.add
              local.get 4
              call $memcpy
              drop
              local.get 5
              local.get 1
              local.get 9
              local.get 4
              i32.add
              local.tee 9
              i32.add
              local.get 4
              call $memcpy
              drop
              local.get 9
              local.get 4
              i32.add
              local.set 9
            end
            local.get 7
            local.get 1
            local.get 9
            i32.add
            local.get 12
            i32.const 2
            i32.shl
            local.tee 4
            call $memcpy
            local.set 12
            local.get 9
            local.get 4
            i32.add
            local.set 2
            local.get 15
            i32.eqz
            br_if 1 (;@3;)
            local.get 18
            local.get 14
            i32.mul
            local.tee 4
            local.get 16
            i32.mul
            i64.extend_i32_s
            local.tee 19
            i64.const 4
            call $calloc
            local.set 8
            block  ;; label = @5
              local.get 4
              i32.const 1
              i32.lt_s
              br_if 0 (;@5;)
              local.get 16
              i32.const 2
              i32.shl
              local.set 6
              local.get 16
              i64.extend_i32_u
              local.tee 20
              i64.const 4294967294
              i64.and
              local.set 21
              local.get 20
              i64.const 1
              i64.and
              local.set 22
              local.get 4
              i32.const 3
              i32.shl
              local.set 9
              local.get 4
              i32.const 2
              i32.shl
              local.set 11
              local.get 4
              i64.extend_i32_u
              local.set 23
              i64.const 0
              local.set 24
              local.get 12
              local.set 10
              local.get 8
              local.set 5
              loop  ;; label = @6
                block  ;; label = @7
                  local.get 16
                  i32.const 1
                  i32.lt_s
                  br_if 0 (;@7;)
                  i64.const 0
                  local.set 20
                  block  ;; label = @8
                    local.get 16
                    i32.const 1
                    i32.eq
                    br_if 0 (;@8;)
                    i64.const 0
                    local.set 20
                    local.get 10
                    local.set 4
                    local.get 5
                    local.set 7
                    loop  ;; label = @9
                      local.get 7
                      local.get 4
                      f32.load
                      f32.store
                      local.get 7
                      local.get 11
                      i32.add
                      local.get 4
                      i32.const 4
                      i32.add
                      f32.load
                      f32.store
                      local.get 4
                      i32.const 8
                      i32.add
                      local.set 4
                      local.get 7
                      local.get 9
                      i32.add
                      local.set 7
                      local.get 21
                      local.get 20
                      i64.const 2
                      i64.add
                      local.tee 20
                      i64.ne
                      br_if 0 (;@9;)
                    end
                  end
                  local.get 22
                  i64.eqz
                  br_if 0 (;@7;)
                  local.get 8
                  local.get 20
                  local.get 23
                  i64.mul
                  local.get 24
                  i64.add
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  local.get 12
                  local.get 20
                  local.get 24
                  local.get 17
                  i64.mul
                  i64.add
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  f32.load
                  f32.store
                end
                local.get 10
                local.get 6
                i32.add
                local.set 10
                local.get 5
                i32.const 4
                i32.add
                local.set 5
                local.get 24
                i64.const 1
                i64.add
                local.tee 24
                local.get 23
                i64.ne
                br_if 0 (;@6;)
              end
            end
            local.get 12
            local.get 8
            local.get 19
            i32.wrap_i64
            i32.const 2
            i32.shl
            call $memcpy
            drop
            local.get 8
            call $free
            br 1 (;@3;)
          end
          local.get 4
          i32.const 84
          i32.add
          i32.load
          local.set 16
          local.get 9
          local.get 1
          local.get 2
          i32.add
          local.get 4
          i32.const 88
          i32.add
          i32.load
          local.tee 12
          i64.extend_i32_s
          i64.const 2
          i64.shl
          i32.wrap_i64
          local.tee 4
          call $memcpy
          drop
          local.get 7
          local.get 1
          local.get 2
          local.get 4
          i32.add
          local.tee 9
          i32.add
          local.get 12
          local.get 16
          i32.mul
          i32.const 2
          i32.shl
          local.tee 16
          call $memcpy
          drop
          local.get 9
          local.get 16
          i32.add
          local.set 2
          local.get 11
          i32.eqz
          br_if 0 (;@3;)
          local.get 10
          br_if 0 (;@3;)
          local.get 8
          local.get 1
          local.get 2
          i32.add
          local.get 4
          call $memcpy
          drop
          local.get 6
          local.get 1
          local.get 2
          local.get 4
          i32.add
          local.tee 7
          i32.add
          local.get 4
          call $memcpy
          drop
          local.get 5
          local.get 1
          local.get 7
          local.get 4
          i32.add
          local.tee 7
          i32.add
          local.get 4
          call $memcpy
          drop
          local.get 7
          local.get 4
          i32.add
          local.set 2
        end
        local.get 3
        i64.const 1
        i64.add
        local.tee 3
        local.get 0
        i64.load32_s
        i64.lt_s
        br_if 0 (;@2;)
      end
    end)
  (func $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_ (type 18) (param i32 i64 i64 i32 i32)
    (local i32)
    local.get 3
    local.get 3
    i32.load
    local.get 2
    local.get 1
    i64.mul
    local.tee 2
    local.get 4
    i64.load32_s
    i64.add
    call $realloc
    local.tee 5
    i32.store
    local.get 5
    local.get 4
    i32.load
    local.tee 3
    i32.add
    local.get 0
    local.get 2
    i32.wrap_i64
    local.tee 5
    call $memcpy
    drop
    local.get 4
    local.get 3
    local.get 5
    i32.add
    i32.store)
  (func $save_connected_weights_layer__char**__int*_ (type 14) (param i32 i32 i32)
    (local i32 i32 i64 i32 i32 i32 i64)
    local.get 0
    i32.load offset=432
    local.set 3
    local.get 1
    local.get 1
    i32.load
    local.get 0
    i32.load offset=60
    local.tee 4
    i64.extend_i32_s
    i64.const 2
    i64.shl
    local.tee 5
    local.get 2
    i64.load32_s
    i64.add
    call $realloc
    local.tee 6
    i32.store
    local.get 6
    local.get 2
    i32.load
    local.tee 7
    i32.add
    local.get 3
    local.get 5
    i32.wrap_i64
    local.tee 8
    call $memcpy
    drop
    local.get 2
    local.get 7
    local.get 8
    i32.add
    local.tee 3
    i32.store
    local.get 0
    i32.load offset=448
    local.set 7
    local.get 1
    local.get 6
    local.get 4
    local.get 0
    i32.load offset=56
    i32.mul
    i64.extend_i32_s
    i64.const 2
    i64.shl
    local.tee 9
    local.get 3
    i64.extend_i32_s
    i64.add
    call $realloc
    local.tee 6
    i32.store
    local.get 6
    local.get 3
    i32.add
    local.get 7
    local.get 9
    i32.wrap_i64
    local.tee 4
    call $memcpy
    drop
    local.get 2
    local.get 3
    local.get 4
    i32.add
    local.tee 3
    i32.store
    block  ;; label = @1
      local.get 0
      i32.load offset=36
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=440
      local.set 4
      local.get 1
      local.get 6
      local.get 5
      local.get 3
      i64.extend_i32_s
      i64.add
      call $realloc
      local.tee 6
      i32.store
      local.get 6
      local.get 3
      i32.add
      local.get 4
      local.get 8
      call $memcpy
      drop
      local.get 2
      local.get 3
      local.get 8
      i32.add
      local.tee 3
      i32.store
      local.get 0
      i32.load offset=496
      local.set 4
      local.get 1
      local.get 6
      local.get 5
      local.get 3
      i64.extend_i32_s
      i64.add
      call $realloc
      local.tee 6
      i32.store
      local.get 6
      local.get 3
      i32.add
      local.get 4
      local.get 8
      call $memcpy
      drop
      local.get 2
      local.get 3
      local.get 8
      i32.add
      local.tee 3
      i32.store
      local.get 0
      i32.load offset=500
      local.set 0
      local.get 1
      local.get 6
      local.get 5
      local.get 3
      i64.extend_i32_s
      i64.add
      call $realloc
      local.tee 6
      i32.store
      local.get 6
      local.get 3
      i32.add
      local.get 0
      local.get 8
      call $memcpy
      drop
      local.get 2
      local.get 3
      local.get 8
      i32.add
      i32.store
    end)
  (func $save_convolutional_weights_layer__char**__int*_ (type 14) (param i32 i32 i32)
    (local i64 i32 i64 i32 i32 i32)
    local.get 0
    i64.load32_s offset=64
    local.set 3
    local.get 0
    i32.load offset=432
    local.set 4
    local.get 1
    local.get 1
    i32.load
    local.get 0
    i64.load32_s offset=104
    i64.const 2
    i64.shl
    local.tee 5
    local.get 2
    i64.load32_s
    i64.add
    call $realloc
    local.tee 6
    i32.store
    local.get 6
    local.get 2
    i32.load
    local.tee 7
    i32.add
    local.get 4
    local.get 5
    i32.wrap_i64
    local.tee 8
    call $memcpy
    drop
    local.get 2
    local.get 7
    local.get 8
    i32.add
    local.tee 4
    i32.store
    block  ;; label = @1
      local.get 0
      i32.load offset=36
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=440
      local.set 7
      local.get 1
      local.get 6
      local.get 5
      local.get 4
      i64.extend_i32_s
      i64.add
      call $realloc
      local.tee 6
      i32.store
      local.get 6
      local.get 4
      i32.add
      local.get 7
      local.get 8
      call $memcpy
      drop
      local.get 2
      local.get 4
      local.get 8
      i32.add
      local.tee 4
      i32.store
      local.get 0
      i32.load offset=496
      local.set 7
      local.get 1
      local.get 6
      local.get 5
      local.get 4
      i64.extend_i32_s
      i64.add
      call $realloc
      local.tee 6
      i32.store
      local.get 6
      local.get 4
      i32.add
      local.get 7
      local.get 8
      call $memcpy
      drop
      local.get 2
      local.get 4
      local.get 8
      i32.add
      local.tee 4
      i32.store
      local.get 0
      i32.load offset=500
      local.set 7
      local.get 1
      local.get 6
      local.get 5
      local.get 4
      i64.extend_i32_s
      i64.add
      call $realloc
      local.tee 6
      i32.store
      local.get 6
      local.get 4
      i32.add
      local.get 7
      local.get 8
      call $memcpy
      drop
      local.get 2
      local.get 4
      local.get 8
      i32.add
      local.tee 4
      i32.store
    end
    local.get 0
    i32.load offset=448
    local.set 0
    local.get 1
    local.get 6
    local.get 3
    i64.const 2
    i64.shl
    local.tee 5
    local.get 4
    i64.extend_i32_s
    i64.add
    call $realloc
    local.tee 8
    i32.store
    local.get 8
    local.get 4
    i32.add
    local.get 0
    local.get 5
    i32.wrap_i64
    local.tee 1
    call $memcpy
    drop
    local.get 2
    local.get 4
    local.get 1
    i32.add
    i32.store)
  (func $save_weights_network*_ (type 3) (param i32)
    (local i32 i32 i32 i64 i32 i32 i32 i32 i32 i32 i32 i64 i64 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.load
        i32.const 1
        i32.ge_s
        br_if 0 (;@2;)
        i32.const 0
        local.set 1
        i32.const 0
        local.set 2
        br 1 (;@1;)
      end
      i32.const 0
      local.set 3
      i64.const 0
      local.set 4
      i32.const 0
      local.set 2
      i32.const 0
      local.set 1
      loop  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=24
          local.get 3
          i32.add
          local.tee 5
          i32.const 344
          i32.add
          i32.load
          br_if 0 (;@3;)
          local.get 5
          i32.const 640
          i32.add
          i32.load
          local.set 6
          local.get 5
          i32.const 632
          i32.add
          i32.load
          local.set 7
          local.get 5
          i32.const 536
          i32.add
          i32.load
          local.set 8
          local.get 5
          i32.const 520
          i32.add
          i32.load
          local.set 9
          local.get 5
          i32.const 504
          i32.add
          i32.load
          local.set 10
          local.get 5
          i32.const 64
          i32.add
          i32.load
          local.set 11
          block  ;; label = @4
            block  ;; label = @5
              local.get 5
              i32.load
              br_table 0 (;@5;) 2 (;@3;) 1 (;@4;) 2 (;@3;)
            end
            local.get 5
            i32.const 92
            i32.add
            i64.load32_s
            local.set 12
            local.get 2
            local.get 5
            i32.const 132
            i32.add
            i64.load32_s
            i64.const 2
            i64.shl
            local.tee 13
            local.get 1
            i64.extend_i32_s
            i64.add
            call $realloc
            local.tee 14
            local.get 1
            i32.add
            local.get 10
            local.get 13
            i32.wrap_i64
            local.tee 2
            call $memcpy
            drop
            local.get 1
            local.get 2
            i32.add
            local.set 5
            block  ;; label = @5
              local.get 11
              i32.eqz
              br_if 0 (;@5;)
              local.get 14
              local.get 13
              local.get 5
              i64.extend_i32_s
              i64.add
              call $realloc
              local.tee 1
              local.get 5
              i32.add
              local.get 9
              local.get 2
              call $memcpy
              drop
              local.get 1
              local.get 13
              local.get 5
              local.get 2
              i32.add
              local.tee 5
              i64.extend_i32_s
              i64.add
              call $realloc
              local.tee 1
              local.get 5
              i32.add
              local.get 7
              local.get 2
              call $memcpy
              drop
              local.get 1
              local.get 13
              local.get 5
              local.get 2
              i32.add
              local.tee 5
              i64.extend_i32_s
              i64.add
              call $realloc
              local.tee 14
              local.get 5
              i32.add
              local.get 6
              local.get 2
              call $memcpy
              drop
              local.get 5
              local.get 2
              i32.add
              local.set 5
            end
            local.get 14
            local.get 12
            i64.const 2
            i64.shl
            local.tee 13
            local.get 5
            i64.extend_i32_s
            i64.add
            call $realloc
            local.tee 2
            local.get 5
            i32.add
            local.get 8
            local.get 13
            i32.wrap_i64
            local.tee 1
            call $memcpy
            drop
            local.get 5
            local.get 1
            i32.add
            local.set 1
            br 1 (;@3;)
          end
          local.get 5
          i32.const 84
          i32.add
          i32.load
          local.set 14
          local.get 2
          local.get 5
          i32.const 88
          i32.add
          i32.load
          local.tee 15
          i64.extend_i32_s
          i64.const 2
          i64.shl
          local.tee 13
          local.get 1
          i64.extend_i32_s
          i64.add
          call $realloc
          local.tee 2
          local.get 1
          i32.add
          local.get 10
          local.get 13
          i32.wrap_i64
          local.tee 5
          call $memcpy
          drop
          local.get 2
          local.get 15
          local.get 14
          i32.mul
          i64.extend_i32_s
          i64.const 2
          i64.shl
          local.tee 12
          local.get 1
          local.get 5
          i32.add
          local.tee 1
          i64.extend_i32_s
          i64.add
          call $realloc
          local.tee 2
          local.get 1
          i32.add
          local.get 8
          local.get 12
          i32.wrap_i64
          local.tee 10
          call $memcpy
          drop
          local.get 1
          local.get 10
          i32.add
          local.set 1
          local.get 11
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          local.get 13
          local.get 1
          i64.extend_i32_s
          i64.add
          call $realloc
          local.tee 2
          local.get 1
          i32.add
          local.get 9
          local.get 5
          call $memcpy
          drop
          local.get 2
          local.get 13
          local.get 1
          local.get 5
          i32.add
          local.tee 1
          i64.extend_i32_s
          i64.add
          call $realloc
          local.tee 2
          local.get 1
          i32.add
          local.get 7
          local.get 5
          call $memcpy
          drop
          local.get 2
          local.get 13
          local.get 1
          local.get 5
          i32.add
          local.tee 1
          i64.extend_i32_s
          i64.add
          call $realloc
          local.tee 2
          local.get 1
          i32.add
          local.get 6
          local.get 5
          call $memcpy
          drop
          local.get 1
          local.get 5
          i32.add
          local.set 1
        end
        local.get 3
        i32.const 752
        i32.add
        local.set 3
        local.get 4
        i64.const 1
        i64.add
        local.tee 4
        local.get 0
        i64.load32_s
        i64.lt_s
        br_if 0 (;@2;)
      end
    end
    local.get 2
    i64.const 1
    local.get 1
    i64.extend_i32_s
    call $ocall_push_weights
    drop)
  (func $network_predict_data_network*__data_ (type 14) (param i32 i32 i32)
    (local i32 i32 i32 i32 i64 i32 i32 i32 i64 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i32 i32 i64 i32 i32 i64 i64 i64 i64 i32 i32 i64)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 2
    i32.load offset=8
    local.tee 4
    local.get 1
    i32.load offset=108
    local.tee 5
    call $make_matrix
    local.get 3
    i32.load offset=8
    local.set 6
    local.get 3
    i64.load
    local.set 7
    local.get 2
    i32.const 12
    i32.add
    i32.load
    local.tee 8
    local.get 1
    i32.load offset=4
    local.tee 9
    i32.mul
    i64.extend_i32_s
    i64.const 4
    call $calloc
    local.set 10
    block  ;; label = @1
      local.get 4
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      local.get 8
      i64.extend_i32_s
      i64.const 2
      i64.shl
      local.set 11
      local.get 2
      i32.const 16
      i32.add
      i32.load
      local.set 12
      local.get 5
      i32.const 2
      i32.shl
      local.set 13
      local.get 8
      i32.const 2
      i32.shl
      local.set 14
      local.get 5
      i64.extend_i32_u
      local.tee 15
      i64.const 3
      i64.and
      local.set 16
      i64.const 0
      local.get 15
      i64.const 4294967288
      i64.and
      local.tee 17
      i64.const -8
      i64.add
      local.tee 18
      i64.const 3
      i64.shr_u
      i64.const 1
      i64.add
      local.tee 19
      i64.const 3
      i64.and
      local.tee 20
      i64.sub
      local.set 21
      i64.const 0
      local.get 19
      i64.const 4611686018427387900
      i64.and
      i64.sub
      local.set 22
      local.get 5
      i64.extend_i32_s
      local.set 23
      i32.const 0
      local.set 24
      local.get 5
      i32.const 8
      i32.lt_u
      local.set 25
      loop  ;; label = @2
        block  ;; label = @3
          local.get 9
          i32.const 1
          i32.lt_s
          br_if 0 (;@3;)
          local.get 12
          local.get 24
          i32.const 2
          i32.shl
          i32.add
          local.set 2
          local.get 4
          local.get 24
          i32.sub
          i64.extend_i32_u
          local.set 19
          local.get 9
          i64.extend_i32_u
          local.set 26
          local.get 10
          local.set 8
          loop  ;; label = @4
            local.get 19
            i64.eqz
            br_if 1 (;@3;)
            local.get 2
            i32.load
            local.set 27
            local.get 19
            i64.const -1
            i64.add
            local.set 19
            local.get 2
            i32.const 4
            i32.add
            local.set 2
            local.get 8
            local.get 27
            local.get 11
            i32.wrap_i64
            call $memcpy
            local.get 14
            i32.add
            local.set 8
            local.get 26
            i64.const -1
            i64.add
            local.tee 26
            i64.const 0
            i64.ne
            br_if 0 (;@4;)
          end
        end
        local.get 1
        local.get 10
        call $network_predict
        local.set 28
        block  ;; label = @3
          local.get 1
          i32.load offset=4
          local.tee 9
          i32.const 1
          i32.lt_s
          br_if 0 (;@3;)
          local.get 4
          local.get 24
          i32.sub
          i64.extend_i32_u
          local.set 29
          local.get 9
          i64.extend_i32_u
          local.set 30
          local.get 24
          i64.extend_i32_s
          local.set 31
          i64.const 0
          local.set 32
          local.get 28
          local.set 33
          loop  ;; label = @4
            local.get 32
            local.get 29
            i64.eq
            br_if 1 (;@3;)
            block  ;; label = @5
              local.get 5
              i32.const 1
              i32.lt_s
              br_if 0 (;@5;)
              local.get 6
              local.get 32
              local.get 31
              i64.add
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              i32.load
              local.set 34
              i64.const 0
              local.set 19
              block  ;; label = @6
                local.get 25
                br_if 0 (;@6;)
                block  ;; label = @7
                  local.get 34
                  local.get 28
                  local.get 32
                  local.get 23
                  i64.mul
                  local.tee 26
                  local.get 15
                  i64.add
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.ge_u
                  br_if 0 (;@7;)
                  local.get 28
                  local.get 26
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  local.get 34
                  local.get 15
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.lt_u
                  br_if 1 (;@6;)
                end
                i64.const 0
                local.set 19
                block  ;; label = @7
                  local.get 18
                  i64.const 24
                  i64.lt_u
                  br_if 0 (;@7;)
                  i64.const 0
                  local.set 19
                  i32.const 0
                  local.set 27
                  local.get 22
                  local.set 26
                  loop  ;; label = @8
                    local.get 34
                    local.get 27
                    i32.add
                    local.tee 2
                    local.get 33
                    local.get 27
                    i32.add
                    local.tee 8
                    i64.load offset=8 align=4
                    i64.store offset=8 align=4
                    local.get 2
                    local.get 8
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 24
                    i32.add
                    local.get 8
                    i32.const 24
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 16
                    i32.add
                    local.get 8
                    i32.const 16
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 56
                    i32.add
                    local.get 8
                    i32.const 56
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 48
                    i32.add
                    local.get 8
                    i32.const 48
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 40
                    i32.add
                    local.get 8
                    i32.const 40
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 32
                    i32.add
                    local.get 8
                    i32.const 32
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 88
                    i32.add
                    local.get 8
                    i32.const 88
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 80
                    i32.add
                    local.get 8
                    i32.const 80
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 72
                    i32.add
                    local.get 8
                    i32.const 72
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 64
                    i32.add
                    local.get 8
                    i32.const 64
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 120
                    i32.add
                    local.get 8
                    i32.const 120
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 112
                    i32.add
                    local.get 8
                    i32.const 112
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 104
                    i32.add
                    local.get 8
                    i32.const 104
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 96
                    i32.add
                    local.get 8
                    i32.const 96
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 27
                    i32.const 128
                    i32.add
                    local.set 27
                    local.get 19
                    i64.const 32
                    i64.add
                    local.set 19
                    local.get 26
                    i64.const 4
                    i64.add
                    local.tee 26
                    i64.const 0
                    i64.ne
                    br_if 0 (;@8;)
                  end
                end
                block  ;; label = @7
                  local.get 20
                  i64.eqz
                  br_if 0 (;@7;)
                  local.get 19
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  local.set 2
                  local.get 21
                  local.set 19
                  loop  ;; label = @8
                    local.get 34
                    local.get 2
                    i32.add
                    local.tee 8
                    local.get 33
                    local.get 2
                    i32.add
                    local.tee 27
                    i64.load offset=8 align=4
                    i64.store offset=8 align=4
                    local.get 8
                    local.get 27
                    i64.load align=4
                    i64.store align=4
                    local.get 8
                    i32.const 24
                    i32.add
                    local.get 27
                    i32.const 24
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 8
                    i32.const 16
                    i32.add
                    local.get 27
                    i32.const 16
                    i32.add
                    i64.load align=4
                    i64.store align=4
                    local.get 2
                    i32.const 32
                    i32.add
                    local.set 2
                    local.get 19
                    i64.const 1
                    i64.add
                    local.tee 26
                    local.get 19
                    i64.ge_u
                    local.set 8
                    local.get 26
                    local.set 19
                    local.get 8
                    br_if 0 (;@8;)
                  end
                end
                local.get 17
                local.set 19
                local.get 17
                local.get 15
                i64.eq
                br_if 1 (;@5;)
              end
              local.get 19
              i64.const -1
              i64.xor
              local.get 15
              i64.add
              local.set 35
              block  ;; label = @6
                local.get 16
                i64.eqz
                br_if 0 (;@6;)
                local.get 19
                i32.wrap_i64
                i32.const 2
                i32.shl
                local.set 2
                local.get 16
                local.set 26
                loop  ;; label = @7
                  local.get 34
                  local.get 2
                  i32.add
                  local.get 33
                  local.get 2
                  i32.add
                  f32.load
                  f32.store
                  local.get 2
                  i32.const 4
                  i32.add
                  local.set 2
                  local.get 19
                  i64.const 1
                  i64.add
                  local.set 19
                  local.get 26
                  i64.const -1
                  i64.add
                  local.tee 26
                  i64.const 0
                  i64.ne
                  br_if 0 (;@7;)
                end
              end
              local.get 35
              i64.const 3
              i64.lt_u
              br_if 0 (;@5;)
              local.get 15
              local.get 19
              i64.sub
              local.set 26
              local.get 19
              i32.wrap_i64
              i32.const 2
              i32.shl
              local.set 2
              loop  ;; label = @6
                local.get 34
                local.get 2
                i32.add
                local.tee 8
                local.get 33
                local.get 2
                i32.add
                local.tee 27
                f32.load
                f32.store
                local.get 8
                i32.const 4
                i32.add
                local.get 27
                i32.const 4
                i32.add
                f32.load
                f32.store
                local.get 8
                i32.const 8
                i32.add
                local.get 27
                i32.const 8
                i32.add
                f32.load
                f32.store
                local.get 8
                i32.const 12
                i32.add
                local.get 27
                i32.const 12
                i32.add
                f32.load
                f32.store
                local.get 2
                i32.const 16
                i32.add
                local.set 2
                local.get 26
                i64.const -4
                i64.add
                local.tee 26
                i64.const 0
                i64.ne
                br_if 0 (;@6;)
              end
            end
            local.get 33
            local.get 13
            i32.add
            local.set 33
            local.get 32
            i64.const 1
            i64.add
            local.tee 32
            local.get 30
            i64.ne
            br_if 0 (;@4;)
          end
        end
        local.get 9
        local.get 24
        i32.add
        local.tee 24
        local.get 4
        i32.lt_s
        br_if 0 (;@2;)
      end
    end
    local.get 10
    call $free
    local.get 0
    local.get 6
    i32.store offset=8
    local.get 0
    local.get 7
    i64.store
    local.get 3
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (table (;0;) 5 5 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 66896))
  (global (;1;) i32 (i32.const 1328))
  (global (;2;) i32 (i32.const 1336))
  (global (;3;) i32 (i32.const 1344))
  (global (;4;) i32 (i32.const 1320))
  (global (;5;) i32 (i32.const 1324))
  (global (;6;) i32 (i32.const 1024))
  (global (;7;) i32 (i32.const 1064))
  (global (;8;) i32 (i32.const 1024))
  (global (;9;) i32 (i32.const 1348))
  (global (;10;) i32 (i32.const 1024))
  (global (;11;) i32 (i32.const 66896))
  (global (;12;) i32 (i32.const 0))
  (global (;13;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "ecall_train_network" (func $ecall_train_network))
  (export "ecall_test_network" (func $ecall_test_network))
  (export "ecall_thread_enter_enclave_waiting" (func $ecall_thread_enter_enclave_waiting))
  (export "ecall_build_network" (func $ecall_build_network))
  (export "ocall_print_string" (func $ocall_print_string))
  (export "ocall_start_measuring_training" (func $ocall_start_measuring_training))
  (export "ocall_end_measuring_training" (func $ocall_end_measuring_training))
  (export "ocall_spawn_threads" (func $ocall_spawn_threads))
  (export "ocall_push_weights" (func $ocall_push_weights))
  (export "printf" (func $printf))
  (export "_Z9free_data4data" (func $free_data_data_))
  (export "_Z16transpose_matrixPfii" (func $transpose_matrix_float*__int__int_))
  (export "_Z10read_bytesPvmmPcPi" (func $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_))
  (export "_Z22load_connected_weights5layerPcPi" (func $load_connected_weights_layer__char*__int*_))
  (export "_Z26load_convolutional_weights5layerPcPi" (func $load_convolutional_weights_layer__char*__int*_))
  (export "_Z12load_weightsP7networkPc" (func $load_weights_network*__char*_))
  (export "_Z11write_bytesPvmmPPcPi" (func $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_))
  (export "_Z22save_connected_weights5layerPPcPi" (func $save_connected_weights_layer__char**__int*_))
  (export "_Z26save_convolutional_weights5layerPPcPi" (func $save_convolutional_weights_layer__char**__int*_))
  (export "_Z12save_weightsP7network" (func $save_weights_network*_))
  (export "g_spin_locks" (global 1))
  (export "g_gemm_args_pointer" (global 2))
  (export "g_finished" (global 3))
  (export "final_net" (global 4))
  (export "g_num_threads" (global 5))
  (export "_Z20network_predict_dataP7network4data" (func $network_predict_data_network*__data_))
  (export "g_ecall_table" (global 6))
  (export "g_dyn_entry_table" (global 7))
  (export "__indirect_function_table" (table 0))
  (export "__dso_handle" (global 8))
  (export "__data_end" (global 9))
  (export "__global_base" (global 10))
  (export "__heap_base" (global 11))
  (export "__memory_base" (global 12))
  (export "__table_base" (global 13))
  (elem (;0;) (i32.const 1) func $sgx_ecall_train_network $sgx_ecall_test_network $sgx_ecall_thread_enter_enclave_waiting $sgx_ecall_build_network)
  (data $.rodata (i32.const 1024) "\04\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\04\00\00\00\00\00\00\00\05\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00epoch %f finished with loss: %f\00network builded\00no network there to train on..\00ERROR: file_string null \00truth: %.2f, pred: %.2f \00y= %d x %d \00X= %d x %d \00data loaded - Matrices sizes: \00output for first train example: \00"))
