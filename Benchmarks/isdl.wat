(module
  (type (;0;) (func (param i32 i64) (result i32)))
  (type (;1;) (func (param i64) (result i32)))
  (type (;2;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;3;) (func (param i32)))
  (type (;4;) (func (param i32) (result i64)))
  (type (;5;) (func))
  (type (;6;) (func (param i32 i32) (result i32)))
  (type (;7;) (func (param i32 i32 i32) (result i32)))
  (type (;8;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;9;) (func (param i64 i32)))
  (type (;10;) (func (param i64 i64) (result i32)))
  (type (;11;) (func (param i32) (result i32)))
  (type (;12;) (func (param i32 i32 i32 i32 i32 i32 f32 i32 i32 i32 i32 f32 i32 i32)))
  (type (;13;) (func (param i32 i32 i32 i32 i32)))
  (type (;14;) (func (param i32 i32) (result f32)))
  (type (;15;) (func (param i32 i32 i32)))
  (type (;16;) (func (param i32 i64 i32 i64)))
  (type (;17;) (func (param i32 i64 i64) (result i32)))
  (type (;18;) (func (param i32 i32)))
  (type (;19;) (func (param i32 i64 i64 i32 i32)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "malloc" (func $malloc (type 1)))
  (import "env" "memcpy_s" (func $memcpy_s (type 2)))
  (import "env" "free" (func $free (type 3)))
  (import "env" "strlen" (func $strlen (type 4)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 1)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 5)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 6)))
  (import "env" "memset" (func $memset (type 7)))
  (import "env" "vsnprintf" (func $vsnprintf (type 8)))
  (import "env" "free_matrix" (func $free_matrix (type 9)))
  (import "env" "calloc" (func $calloc (type 10)))
  (import "env" "memcpy" (func $memcpy (type 7)))
  (import "env" "realloc" (func $realloc (type 0)))
  (import "env" "sgx_spin_lock" (func $sgx_spin_lock (type 11)))
  (import "env" "gemm_cpu" (func $gemm_cpu (type 12)))
  (import "env" "sgx_spin_unlock" (func $sgx_spin_unlock (type 11)))
  (import "env" "sgx_file_string_to_list" (func $sgx_file_string_to_list (type 11)))
  (import "env" "sgx_parse_network_cfg" (func $sgx_parse_network_cfg (type 11)))
  (import "env" "free_list" (func $free_list (type 3)))
  (import "env" "load_categorical_data_csv" (func $load_categorical_data_csv (type 13)))
  (import "env" "get_current_batch" (func $get_current_batch (type 4)))
  (import "env" "train_network" (func $train_network (type 14)))
  (import "env" "network_predict" (func $network_predict (type 6)))
  (import "env" "free_network" (func $free_network (type 3)))
  (import "env" "make_matrix" (func $make_matrix (type 15)))
  (func $__wasm_call_ctors (type 5))
  (func $sgx_ecall_train_network (type 11) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load offset=4
      i32.store offset=20
      local.get 1
      local.get 1
      i32.load offset=20
      i64.extend_i32_s
      i64.const 0
      i64.shl
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
      block  ;; label = @2
        local.get 1
        i32.load offset=20
        i64.extend_i32_s
        i64.const -1
        i64.gt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=8
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=8
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=8
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          i32.store
          block  ;; label = @4
            local.get 1
            i32.load
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load
        local.get 1
        i32.load offset=20
        local.get 1
        i32.load offset=32
        i32.load offset=8
        call $ecall_train_network
      end
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_train_network (type 15) (param i32 i32 i32)
    (local i32 f32)
    global.get $__stack_pointer
    i32.const 336
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=328
    local.get 3
    local.get 1
    i32.store offset=324
    local.get 3
    local.get 2
    i32.store offset=320
    i32.const 0
    local.get 3
    i32.load offset=320
    i32.store offset=1324
    i32.const 0
    i32.const 0
    i32.load offset=1324
    i64.extend_i32_s
    i64.const 4
    call $calloc
    i32.store offset=1328
    i32.const 0
    i32.const 0
    i32.load offset=1324
    i64.extend_i32_s
    i64.const 80
    call $calloc
    i32.store offset=1336
    i32.const 0
    i32.const 0
    i32.load offset=1324
    i64.extend_i32_s
    i64.const 4
    call $calloc
    i32.store offset=1344
    local.get 3
    i32.const 272
    i32.add
    local.get 3
    i32.load offset=328
    local.get 3
    i32.load offset=324
    i32.const 0
    i32.const 10
    call $load_categorical_data_csv
    local.get 3
    local.get 3
    i32.load offset=280
    i32.store offset=268
    local.get 3
    local.get 3
    i32.load offset=268
    i32.store offset=280
    local.get 3
    local.get 3
    i32.load offset=268
    i32.store offset=292
    i32.const 1249
    i32.const 0
    call $printf
    local.get 3
    i32.load offset=284
    local.set 2
    local.get 3
    local.get 3
    i32.load offset=280
    i32.store offset=132
    local.get 3
    local.get 2
    i32.store offset=128
    i32.const 1237
    local.get 3
    i32.const 128
    i32.add
    call $printf
    local.get 3
    i32.load offset=296
    local.set 2
    local.get 3
    local.get 3
    i32.load offset=292
    i32.store offset=148
    local.get 3
    local.get 2
    i32.store offset=144
    i32.const 1225
    local.get 3
    i32.const 144
    i32.add
    call $printf
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=1320
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        br_if 0 (;@2;)
        i32.const 1144
        i32.const 0
        call $printf
        br 1 (;@1;)
      end
      local.get 3
      i32.const 0
      f32.convert_i32_s
      f32.store offset=264
      local.get 3
      i32.const 0
      f32.convert_i32_s
      f32.store offset=260
      local.get 3
      i32.const 0
      i32.store offset=256
      block  ;; label = @2
        loop  ;; label = @3
          local.get 3
          i32.load offset=256
          i32.const 0
          i32.load offset=1324
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          i32.const 0
          i32.load offset=1328
          local.get 3
          i32.load offset=256
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          call $sgx_spin_lock
          drop
          local.get 3
          local.get 3
          i32.load offset=256
          i32.const 1
          i32.add
          i32.store offset=256
          br 0 (;@3;)
        end
      end
      i32.const 0
      i32.load offset=1324
      call $ocall_spawn_threads
      drop
      i32.const 0
      i32.const 1
      call $ocall_start_measuring_training
      drop
      loop  ;; label = @2
        i32.const 1
        local.set 2
        block  ;; label = @3
          i32.const 0
          i32.load offset=1320
          call $get_current_batch
          i32.const 0
          i32.load offset=1320
          i32.load offset=68
          i64.extend_i32_s
          i64.lt_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          i32.const 0
          i32.load offset=1320
          i32.load offset=68
          i32.const 0
          i32.eq
          local.set 2
        end
        block  ;; label = @3
          local.get 2
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          i32.const 0
          i32.load offset=1320
          local.set 0
          local.get 3
          i32.const 208
          i32.add
          local.tee 2
          local.get 3
          i32.const 272
          i32.add
          local.tee 1
          i64.load
          i64.store
          local.get 2
          i32.const 56
          i32.add
          local.get 1
          i32.const 56
          i32.add
          i64.load
          i64.store
          local.get 2
          i32.const 48
          i32.add
          local.get 1
          i32.const 48
          i32.add
          i64.load
          i64.store
          local.get 2
          i32.const 40
          i32.add
          local.get 1
          i32.const 40
          i32.add
          i64.load
          i64.store
          local.get 2
          i32.const 32
          i32.add
          local.get 1
          i32.const 32
          i32.add
          i64.load
          i64.store
          local.get 2
          i32.const 24
          i32.add
          local.get 1
          i32.const 24
          i32.add
          i64.load
          i64.store
          local.get 2
          i32.const 16
          i32.add
          local.get 1
          i32.const 16
          i32.add
          i64.load
          i64.store
          local.get 2
          i32.const 8
          i32.add
          local.get 1
          i32.const 8
          i32.add
          i64.load
          i64.store
          local.get 3
          i32.const 16
          i32.add
          i32.const 40
          i32.add
          local.get 3
          i32.const 208
          i32.add
          i32.const 40
          i32.add
          i32.load
          i32.store
          local.get 3
          i32.const 16
          i32.add
          i32.const 32
          i32.add
          local.get 3
          i32.const 208
          i32.add
          i32.const 32
          i32.add
          i64.load
          i64.store
          local.get 3
          i32.const 16
          i32.add
          i32.const 24
          i32.add
          local.get 3
          i32.const 208
          i32.add
          i32.const 24
          i32.add
          i64.load
          i64.store
          local.get 3
          i32.const 16
          i32.add
          i32.const 16
          i32.add
          local.get 3
          i32.const 208
          i32.add
          i32.const 16
          i32.add
          i64.load
          i64.store
          local.get 3
          i32.const 16
          i32.add
          i32.const 8
          i32.add
          local.get 3
          i32.const 208
          i32.add
          i32.const 8
          i32.add
          i64.load
          i64.store
          local.get 3
          local.get 3
          i64.load offset=208
          i64.store offset=16
          local.get 3
          local.get 0
          local.get 3
          i32.const 16
          i32.add
          call $train_network
          f32.store offset=264
          block  ;; label = @4
            local.get 3
            f32.load offset=264
            f32.const -0x1p+0 (;=-1;)
            f32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            br 3 (;@1;)
          end
          local.get 3
          i32.const 0
          i32.load offset=1320
          i32.load offset=8
          i64.load
          f32.convert_i64_u
          local.get 3
          i32.load offset=268
          f32.convert_i32_s
          f32.div
          f32.store offset=260
          local.get 3
          f32.load offset=260
          local.set 4
          local.get 3
          local.get 3
          f32.load offset=264
          f64.promote_f32
          f64.store offset=8
          local.get 3
          local.get 4
          f64.promote_f32
          f64.store
          i32.const 1096
          local.get 3
          call $printf
          br 1 (;@2;)
        end
      end
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
      local.get 3
      i32.const 0
      i32.load offset=1320
      local.get 3
      i32.load offset=288
      i32.load
      call $network_predict
      i32.store offset=200
      local.get 3
      i32.const 0
      i32.store offset=256
      block  ;; label = @2
        loop  ;; label = @3
          local.get 3
          i32.load offset=256
          local.get 3
          i32.load offset=296
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 3
          i32.const 300
          i32.add
          i32.load
          i32.load
          local.get 3
          i32.load offset=256
          i32.const 2
          i32.shl
          local.tee 2
          i32.add
          f32.load
          local.set 4
          local.get 3
          local.get 3
          i32.load offset=200
          local.get 2
          i32.add
          f32.load
          f64.promote_f32
          f64.store offset=72
          local.get 3
          local.get 4
          f64.promote_f32
          f64.store offset=64
          i32.const 1200
          local.get 3
          i32.const 64
          i32.add
          call $printf
          local.get 3
          local.get 3
          i32.load offset=256
          i32.const 1
          i32.add
          i32.store offset=256
          br 0 (;@3;)
        end
      end
      local.get 3
      i32.const 152
      i32.add
      local.tee 2
      local.get 3
      i32.const 272
      i32.add
      local.tee 1
      i64.load
      i64.store
      local.get 2
      i32.const 56
      i32.add
      local.get 1
      i32.const 56
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 48
      i32.add
      local.get 1
      i32.const 48
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 40
      i32.add
      local.get 1
      i32.const 40
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 32
      i32.add
      local.get 1
      i32.const 32
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 24
      i32.add
      local.get 1
      i32.const 24
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 16
      i32.add
      local.get 1
      i32.const 16
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 8
      i32.add
      local.get 1
      i32.const 8
      i32.add
      i64.load
      i64.store
      local.get 3
      i32.const 80
      i32.add
      i32.const 40
      i32.add
      local.get 3
      i32.const 152
      i32.add
      i32.const 40
      i32.add
      i32.load
      i32.store
      local.get 3
      i32.const 80
      i32.add
      i32.const 32
      i32.add
      local.get 3
      i32.const 152
      i32.add
      i32.const 32
      i32.add
      i64.load
      i64.store
      local.get 3
      i32.const 80
      i32.add
      i32.const 24
      i32.add
      local.get 3
      i32.const 152
      i32.add
      i32.const 24
      i32.add
      i64.load
      i64.store
      local.get 3
      i32.const 80
      i32.add
      i32.const 16
      i32.add
      local.get 3
      i32.const 152
      i32.add
      i32.const 16
      i32.add
      i64.load
      i64.store
      local.get 3
      i32.const 80
      i32.add
      i32.const 8
      i32.add
      local.get 3
      i32.const 152
      i32.add
      i32.const 8
      i32.add
      i64.load
      i64.store
      local.get 3
      local.get 3
      i64.load offset=152
      i64.store offset=80
      local.get 3
      i32.const 80
      i32.add
      call $free_data_data_
      i32.const 0
      i32.load offset=1320
      call $free_network
    end
    local.get 3
    i32.const 336
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_test_network (type 11) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load offset=4
      i32.store offset=20
      local.get 1
      local.get 1
      i32.load offset=20
      i64.extend_i32_s
      i64.const 0
      i64.shl
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
      block  ;; label = @2
        local.get 1
        i32.load offset=20
        i64.extend_i32_s
        i64.const -1
        i64.gt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=8
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=8
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=8
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          i32.store
          block  ;; label = @4
            local.get 1
            i32.load
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load
        local.get 1
        i32.load offset=20
        local.get 1
        i32.load offset=32
        i32.load offset=8
        call $ecall_test_network
      end
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_test_network (type 15) (param i32 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 176
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=168
    local.get 3
    local.get 1
    i32.store offset=164
    local.get 3
    local.get 2
    i32.store offset=160
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=1320
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 0
      local.get 3
      i32.load offset=160
      i32.store offset=1324
      i32.const 0
      i32.const 0
      i32.load offset=1324
      i64.extend_i32_s
      i64.const 4
      call $calloc
      i32.store offset=1328
      i32.const 0
      i32.const 0
      i32.load offset=1324
      i64.extend_i32_s
      i64.const 80
      call $calloc
      i32.store offset=1336
      i32.const 0
      i32.const 0
      i32.load offset=1324
      i64.extend_i32_s
      i64.const 4
      call $calloc
      i32.store offset=1344
      local.get 3
      i32.const 0
      i32.store offset=156
      block  ;; label = @2
        loop  ;; label = @3
          local.get 3
          i32.load offset=156
          i32.const 0
          i32.load offset=1324
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          i32.const 0
          i32.load offset=1328
          local.get 3
          i32.load offset=156
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          call $sgx_spin_lock
          drop
          local.get 3
          local.get 3
          i32.load offset=156
          i32.const 1
          i32.add
          i32.store offset=156
          br 0 (;@3;)
        end
      end
      i32.const 0
      i32.load offset=1324
      call $ocall_spawn_threads
      drop
      local.get 3
      i32.const 112
      i32.add
      local.get 3
      i32.load offset=168
      local.get 3
      i32.load offset=164
      i32.const 0
      i32.const 10
      call $load_categorical_data_csv
      local.get 3
      i32.const 0
      f32.convert_i32_s
      f32.store offset=108
      local.get 3
      i32.const 0
      i32.store offset=156
      block  ;; label = @2
        loop  ;; label = @3
          local.get 3
          i32.load offset=156
          local.get 3
          i32.load offset=120
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 3
          i32.const 0
          i32.load offset=1320
          local.get 3
          i32.load offset=128
          local.get 3
          i32.load offset=156
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          call $network_predict
          i32.store offset=104
          local.get 3
          i32.const 0
          i32.store offset=100
          block  ;; label = @4
            loop  ;; label = @5
              local.get 3
              i32.load offset=140
              local.get 3
              i32.load offset=156
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              i32.load
              local.get 3
              i32.load offset=100
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              f32.load
              i32.const 0
              f32.convert_i32_s
              f32.eq
              i32.const 1
              i32.and
              i32.eqz
              br_if 1 (;@4;)
              local.get 3
              local.get 3
              i32.load offset=100
              i32.const 1
              i32.add
              i32.store offset=100
              br 0 (;@5;)
            end
          end
          local.get 3
          local.get 3
          f32.load offset=108
          f32.const 0x1p+0 (;=1;)
          local.get 3
          i32.load offset=104
          local.get 3
          i32.load offset=100
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          f32.load
          f32.sub
          f32.add
          f32.store offset=108
          local.get 3
          local.get 3
          i32.load offset=156
          i32.const 1
          i32.add
          i32.store offset=156
          br 0 (;@3;)
        end
      end
      local.get 3
      i32.const 56
      i32.add
      local.tee 2
      local.get 3
      i32.const 112
      i32.add
      local.tee 1
      i64.load
      i64.store
      local.get 2
      i32.const 56
      i32.add
      local.get 1
      i32.const 56
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 48
      i32.add
      local.get 1
      i32.const 48
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 40
      i32.add
      local.get 1
      i32.const 40
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 32
      i32.add
      local.get 1
      i32.const 32
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 24
      i32.add
      local.get 1
      i32.const 24
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 16
      i32.add
      local.get 1
      i32.const 16
      i32.add
      i64.load
      i64.store
      local.get 2
      i32.const 8
      i32.add
      local.get 1
      i32.const 8
      i32.add
      i64.load
      i64.store
      local.get 3
      i32.const 8
      i32.add
      i32.const 40
      i32.add
      local.get 3
      i32.const 56
      i32.add
      i32.const 40
      i32.add
      i32.load
      i32.store
      local.get 3
      i32.const 8
      i32.add
      i32.const 32
      i32.add
      local.get 3
      i32.const 56
      i32.add
      i32.const 32
      i32.add
      i64.load
      i64.store
      local.get 3
      i32.const 8
      i32.add
      i32.const 24
      i32.add
      local.get 3
      i32.const 56
      i32.add
      i32.const 24
      i32.add
      i64.load
      i64.store
      local.get 3
      i32.const 8
      i32.add
      i32.const 16
      i32.add
      local.get 3
      i32.const 56
      i32.add
      i32.const 16
      i32.add
      i64.load
      i64.store
      local.get 3
      i32.const 8
      i32.add
      i32.const 8
      i32.add
      local.get 3
      i32.const 56
      i32.add
      i32.const 8
      i32.add
      i64.load
      i64.store
      local.get 3
      local.get 3
      i64.load offset=56
      i64.store offset=8
      local.get 3
      i32.const 8
      i32.add
      call $free_data_data_
      i32.const 0
      i32.load offset=1320
      call $free_network
    end
    local.get 3
    i32.const 176
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_thread_enter_enclave_waiting (type 11) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 4
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      i32.load offset=16
      i32.load
      call $ecall_thread_enter_enclave_waiting
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_thread_enter_enclave_waiting (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=12
    loop  ;; label = @1
      i32.const 0
      i32.load offset=1328
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 2
      i32.shl
      i32.add
      call $sgx_spin_lock
      drop
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=4
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=8
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=12
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=16
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=20
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      f32.load offset=24
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=28
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=32
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=36
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=44
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      f32.load offset=40
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=48
      i32.const 0
      i32.load offset=1336
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 56
      i32.mul
      i32.add
      i32.load offset=52
      call $gemm_cpu
      i32.const 0
      i32.load offset=1344
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 2
      i32.shl
      i32.add
      i32.const 1
      i32.store
      i32.const 0
      i32.load offset=1328
      local.get 1
      i32.load offset=12
      i64.extend_i32_s
      i32.wrap_i64
      i32.const 2
      i32.shl
      i32.add
      call $sgx_spin_unlock
      drop
      block  ;; label = @2
        loop  ;; label = @3
          i32.const 0
          i32.load offset=1344
          local.get 1
          i32.load offset=12
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          i32.const 1
          i32.eq
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          br 0 (;@3;)
        end
      end
      br 0 (;@1;)
    end)
  (func $sgx_ecall_build_network (type 11) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 80
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=72
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=72
          i64.const 32
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=72
      i32.store offset=64
      local.get 1
      i32.const 0
      i32.store offset=60
      local.get 1
      local.get 1
      i32.load offset=64
      i32.load
      i32.store offset=56
      local.get 1
      local.get 1
      i32.load offset=64
      i64.load offset=8
      i64.store offset=48
      local.get 1
      local.get 1
      i64.load offset=48
      i64.const 0
      i64.shl
      i64.store offset=40
      local.get 1
      i32.const 0
      i32.store offset=32
      local.get 1
      local.get 1
      i32.load offset=64
      i32.load offset=16
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=64
      i64.load offset=24
      i64.store offset=16
      local.get 1
      local.get 1
      i64.load offset=16
      i64.const 0
      i64.shl
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
      block  ;; label = @2
        local.get 1
        i64.load offset=48
        i64.const -1
        i64.gt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i64.load offset=16
        i64.const -1
        i64.gt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=56
        local.get 1
        i64.load offset=40
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=8
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=40
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=40
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=60
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=40
          call $malloc
          i32.store offset=32
          block  ;; label = @4
            local.get 1
            i32.load offset=32
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=60
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=32
            local.get 1
            i64.load offset=40
            local.get 1
            i32.load offset=56
            local.get 1
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=60
            br 2 (;@2;)
          end
        end
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=8
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=8
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=60
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          i32.store
          block  ;; label = @4
            local.get 1
            i32.load
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=60
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=60
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=32
        local.get 1
        i64.load offset=48
        local.get 1
        i32.load
        local.get 1
        i64.load offset=16
        call $ecall_build_network
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=32
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=32
        call $free
      end
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=60
      i32.store offset=76
    end
    local.get 1
    i32.load offset=76
    local.set 0
    local.get 1
    i32.const 80
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_build_network (type 16) (param i32 i64 i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=40
    local.get 4
    local.get 1
    i64.store offset=32
    local.get 4
    local.get 2
    i32.store offset=24
    local.get 4
    local.get 3
    i64.store offset=16
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.load offset=40
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        i32.const 1175
        i32.const 0
        call $printf
        br 1 (;@1;)
      end
      local.get 4
      i64.const 272
      call $malloc
      i32.store offset=8
      local.get 4
      local.get 4
      i32.load offset=40
      call $sgx_file_string_to_list
      i32.store
      local.get 4
      local.get 4
      i32.load
      call $sgx_parse_network_cfg
      i32.store offset=8
      local.get 4
      i32.load
      call $free_list
      block  ;; label = @2
        local.get 4
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=8
        local.get 4
        i32.load offset=24
        call $load_weights_network*__char*_
      end
      i32.const 0
      local.get 4
      i32.load offset=8
      i32.store offset=1320
      i32.const 1128
      i32.const 0
      call $printf
    end
    local.get 4
    i32.const 48
    i32.add
    global.set $__stack_pointer)
  (func $ocall_print_string (type 11) (param i32) (result i32)
    (local i32 i64 i64)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    local.get 1
    i32.const 0
    i32.store offset=36
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=40
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=40
        call $strlen
        i64.const 1
        i64.add
        local.set 2
        br 1 (;@1;)
      end
      i64.const 0
      local.set 2
    end
    local.get 1
    local.get 2
    i64.store offset=24
    local.get 1
    i32.const 0
    i32.store offset=16
    local.get 1
    i64.const 8
    i64.store offset=8
    local.get 1
    i32.const 0
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=40
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=40
        local.get 1
        i64.load offset=24
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=24
          local.set 2
          br 1 (;@2;)
        end
        i64.const 0
        local.set 2
      end
      local.get 1
      local.get 1
      i64.load offset=8
      local.get 2
      i64.add
      local.tee 2
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=24
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      block  ;; label = @2
        local.get 2
        local.get 3
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i64.load offset=8
      call $sgx_ocalloc
      i32.store
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 1
        i32.const 1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load
      i32.store offset=16
      local.get 1
      local.get 1
      i32.load
      i64.extend_i32_u
      i64.const 8
      i64.add
      i32.wrap_i64
      i32.store
      local.get 1
      local.get 1
      i64.load offset=8
      i64.const 8
      i64.sub
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=16
          local.get 1
          i32.load
          i32.store
          block  ;; label = @4
            local.get 1
            i64.load offset=24
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 2
            i32.store offset=44
            br 3 (;@1;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=40
            local.get 1
            i64.load offset=24
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 1
            i32.store offset=44
            br 3 (;@1;)
          end
          local.get 1
          local.get 1
          i32.load
          i64.extend_i32_u
          local.get 1
          i64.load offset=24
          i64.add
          i32.wrap_i64
          i32.store
          local.get 1
          local.get 1
          i64.load offset=8
          local.get 1
          i64.load offset=24
          i64.sub
          i64.store offset=8
          br 1 (;@2;)
        end
        local.get 1
        i32.load offset=16
        i32.const 0
        i32.store
      end
      local.get 1
      i32.const 0
      local.get 1
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=36
      block  ;; label = @2
        local.get 1
        i32.load offset=36
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 1
      local.get 1
      i32.load offset=36
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ocall_start_measuring_training (type 6) (param i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=40
    local.get 2
    local.get 1
    i32.store offset=36
    local.get 2
    i32.const 0
    i32.store offset=32
    local.get 2
    i32.const 0
    i32.store offset=24
    local.get 2
    i64.const 8
    i64.store offset=16
    local.get 2
    i32.const 0
    i32.store offset=8
    local.get 2
    local.get 2
    i64.load offset=16
    call $sgx_ocalloc
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=8
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 2
        i32.const 1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 2
      local.get 2
      i32.load offset=8
      i32.store offset=24
      local.get 2
      local.get 2
      i32.load offset=8
      i64.extend_i32_u
      i64.const 8
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 2
      local.get 2
      i64.load offset=16
      i64.const 8
      i64.sub
      i64.store offset=16
      local.get 2
      i32.load offset=24
      local.get 2
      i32.load offset=40
      i32.store
      local.get 2
      i32.load offset=24
      local.get 2
      i32.load offset=36
      i32.store offset=4
      local.get 2
      i32.const 1
      local.get 2
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=32
      block  ;; label = @2
        local.get 2
        i32.load offset=32
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 2
      local.get 2
      i32.load offset=32
      i32.store offset=44
    end
    local.get 2
    i32.load offset=44
    local.set 1
    local.get 2
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $ocall_end_measuring_training (type 6) (param i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=40
    local.get 2
    local.get 1
    i32.store offset=36
    local.get 2
    i32.const 0
    i32.store offset=32
    local.get 2
    i32.const 0
    i32.store offset=24
    local.get 2
    i64.const 8
    i64.store offset=16
    local.get 2
    i32.const 0
    i32.store offset=8
    local.get 2
    local.get 2
    i64.load offset=16
    call $sgx_ocalloc
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=8
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 2
        i32.const 1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 2
      local.get 2
      i32.load offset=8
      i32.store offset=24
      local.get 2
      local.get 2
      i32.load offset=8
      i64.extend_i32_u
      i64.const 8
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 2
      local.get 2
      i64.load offset=16
      i64.const 8
      i64.sub
      i64.store offset=16
      local.get 2
      i32.load offset=24
      local.get 2
      i32.load offset=40
      i32.store
      local.get 2
      i32.load offset=24
      local.get 2
      i32.load offset=36
      i32.store offset=4
      local.get 2
      i32.const 2
      local.get 2
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=32
      block  ;; label = @2
        local.get 2
        i32.load offset=32
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 2
      local.get 2
      i32.load offset=32
      i32.store offset=44
    end
    local.get 2
    i32.load offset=44
    local.set 1
    local.get 2
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $ocall_spawn_threads (type 11) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    local.get 1
    i32.const 0
    i32.store offset=20
    local.get 1
    i32.const 0
    i32.store offset=16
    local.get 1
    i64.const 4
    i64.store offset=8
    local.get 1
    i32.const 0
    i32.store
    local.get 1
    local.get 1
    i64.load offset=8
    call $sgx_ocalloc
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 1
        i32.const 1
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load
      i32.store offset=16
      local.get 1
      local.get 1
      i32.load
      i64.extend_i32_u
      i64.const 4
      i64.add
      i32.wrap_i64
      i32.store
      local.get 1
      local.get 1
      i64.load offset=8
      i64.const 4
      i64.sub
      i64.store offset=8
      local.get 1
      i32.load offset=16
      local.get 1
      i32.load offset=24
      i32.store
      local.get 1
      i32.const 3
      local.get 1
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=20
      block  ;; label = @2
        local.get 1
        i32.load offset=20
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 1
      local.get 1
      i32.load offset=20
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ocall_push_weights (type 17) (param i32 i64 i64) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=56
    local.get 3
    local.get 1
    i64.store offset=48
    local.get 3
    local.get 2
    i64.store offset=40
    local.get 3
    i32.const 0
    i32.store offset=36
    local.get 3
    local.get 3
    i64.load offset=40
    local.get 3
    i64.load offset=48
    i64.mul
    i64.store offset=24
    local.get 3
    i32.const 0
    i32.store offset=16
    local.get 3
    i64.const 24
    i64.store offset=8
    local.get 3
    i32.const 0
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=56
        local.get 3
        i64.load offset=24
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=24
          local.set 2
          br 1 (;@2;)
        end
        i64.const 0
        local.set 2
      end
      local.get 3
      local.get 3
      i64.load offset=8
      local.get 2
      i64.add
      local.tee 2
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=24
          local.set 1
          br 1 (;@2;)
        end
        i64.const 0
        local.set 1
      end
      block  ;; label = @2
        local.get 2
        local.get 1
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i64.load offset=8
      call $sgx_ocalloc
      i32.store
      block  ;; label = @2
        local.get 3
        i32.load
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 3
        i32.const 1
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.load
      i32.store offset=16
      local.get 3
      local.get 3
      i32.load
      i64.extend_i32_u
      i64.const 24
      i64.add
      i32.wrap_i64
      i32.store
      local.get 3
      local.get 3
      i64.load offset=8
      i64.const 24
      i64.sub
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=16
          local.get 3
          i32.load
          i32.store
          block  ;; label = @4
            local.get 3
            i64.load offset=24
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 3
            i32.const 2
            i32.store offset=60
            br 3 (;@1;)
          end
          block  ;; label = @4
            local.get 3
            i32.load
            local.get 3
            i64.load offset=8
            local.get 3
            i32.load offset=56
            local.get 3
            i64.load offset=24
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 3
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 3
          local.get 3
          i32.load
          i64.extend_i32_u
          local.get 3
          i64.load offset=24
          i64.add
          i32.wrap_i64
          i32.store
          local.get 3
          local.get 3
          i64.load offset=8
          local.get 3
          i64.load offset=24
          i64.sub
          i64.store offset=8
          br 1 (;@2;)
        end
        local.get 3
        i32.load offset=16
        i32.const 0
        i32.store
      end
      local.get 3
      i32.load offset=16
      local.get 3
      i64.load offset=48
      i64.store offset=8
      local.get 3
      i32.load offset=16
      local.get 3
      i64.load offset=40
      i64.store offset=16
      local.get 3
      i32.const 4
      local.get 3
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=36
      block  ;; label = @2
        local.get 3
        i32.load offset=36
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 3
      local.get 3
      i32.load offset=36
      i32.store offset=60
    end
    local.get 3
    i32.load offset=60
    local.set 0
    local.get 3
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $printf (type 18) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 8224
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=8216
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
    local.get 2
    i32.load offset=8216
    local.get 2
    call $vsnprintf
    drop
    local.get 2
    drop
    local.get 2
    i32.const 16
    i32.add
    call $ocall_print_string
    drop
    local.get 2
    i32.const 8224
    i32.add
    global.set $__stack_pointer)
  (func $free_data_data_ (type 3) (param i32)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.load offset=32
        br_if 0 (;@2;)
        local.get 1
        i32.const 16
        i32.add
        local.tee 2
        local.get 0
        i32.const 8
        i32.add
        local.tee 3
        i64.load
        i64.store
        local.get 2
        i32.const 8
        i32.add
        local.get 3
        i32.const 8
        i32.add
        i64.load
        i64.store
        local.get 1
        i64.load offset=16
        local.get 1
        i32.load offset=24
        call $free_matrix
        local.get 1
        local.tee 2
        local.get 0
        i32.const 20
        i32.add
        local.tee 0
        i64.load
        i64.store
        local.get 2
        i32.const 8
        i32.add
        local.get 0
        i32.const 8
        i32.add
        i64.load
        i64.store
        local.get 1
        i64.load
        local.get 1
        i32.load offset=8
        call $free_matrix
        br 1 (;@1;)
      end
      local.get 0
      i32.load offset=16
      call $free
      local.get 0
      i32.load offset=28
      call $free
    end
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $transpose_matrix_float*__int__int_ (type 15) (param i32 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=24
    local.get 3
    local.get 1
    i32.store offset=20
    local.get 3
    local.get 2
    i32.store offset=16
    local.get 3
    local.get 3
    i32.load offset=20
    local.get 3
    i32.load offset=16
    i32.mul
    i64.extend_i32_s
    i64.const 4
    call $calloc
    i32.store offset=8
    local.get 3
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      loop  ;; label = @2
        local.get 3
        i32.load offset=4
        local.get 3
        i32.load offset=20
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 3
        i32.const 0
        i32.store
        block  ;; label = @3
          loop  ;; label = @4
            local.get 3
            i32.load
            local.get 3
            i32.load offset=16
            i32.lt_s
            i32.const 1
            i32.and
            i32.eqz
            br_if 1 (;@3;)
            local.get 3
            i32.load offset=8
            local.get 3
            i32.load
            local.get 3
            i32.load offset=20
            i32.mul
            local.get 3
            i32.load offset=4
            i32.add
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            local.get 3
            i32.load offset=24
            local.get 3
            i32.load offset=4
            local.get 3
            i32.load offset=16
            i32.mul
            local.get 3
            i32.load
            i32.add
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            f32.load
            f32.store
            local.get 3
            local.get 3
            i32.load
            i32.const 1
            i32.add
            i32.store
            br 0 (;@4;)
          end
        end
        local.get 3
        local.get 3
        i32.load offset=4
        i32.const 1
        i32.add
        i32.store offset=4
        br 0 (;@2;)
      end
    end
    local.get 3
    i32.load offset=24
    local.get 3
    i32.load offset=8
    local.get 3
    i32.load offset=20
    local.get 3
    i32.load offset=16
    i32.mul
    i64.extend_i32_s
    i64.const 2
    i64.shl
    i32.wrap_i64
    call $memcpy
    drop
    local.get 3
    i32.load offset=8
    call $free
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_ (type 19) (param i32 i64 i64 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    local.get 5
    local.get 0
    i32.store offset=40
    local.get 5
    local.get 1
    i64.store offset=32
    local.get 5
    local.get 2
    i64.store offset=24
    local.get 5
    local.get 3
    i32.store offset=16
    local.get 5
    local.get 4
    i32.store offset=8
    local.get 5
    i32.load offset=40
    local.get 5
    i32.load offset=16
    local.get 5
    i32.load offset=8
    i32.load
    i64.extend_i32_s
    i32.wrap_i64
    i32.add
    local.get 5
    i64.load offset=32
    local.get 5
    i64.load offset=24
    i64.mul
    i32.wrap_i64
    call $memcpy
    drop
    local.get 5
    i32.load offset=8
    local.tee 4
    local.get 4
    i32.load
    i64.extend_i32_s
    local.get 5
    i64.load offset=32
    local.get 5
    i64.load offset=24
    i64.mul
    i64.add
    i32.wrap_i64
    i32.store
    local.get 5
    i32.const 48
    i32.add
    global.set $__stack_pointer)
  (func $load_connected_weights_layer__char*__int*_ (type 15) (param i32 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 1
    i32.store offset=8
    local.get 3
    local.get 2
    i32.store
    local.get 0
    i32.load offset=432
    i64.const 4
    local.get 0
    i32.load offset=60
    i64.extend_i32_s
    local.get 3
    i32.load offset=8
    local.get 3
    i32.load
    call $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_
    local.get 0
    i32.load offset=448
    i64.const 4
    local.get 0
    i32.load offset=60
    local.get 0
    i32.load offset=56
    i32.mul
    i64.extend_i32_s
    local.get 3
    i32.load offset=8
    local.get 3
    i32.load
    call $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_
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
      i64.const 4
      local.get 0
      i32.load offset=60
      i64.extend_i32_s
      local.get 3
      i32.load offset=8
      local.get 3
      i32.load
      call $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_
      local.get 0
      i32.load offset=496
      i64.const 4
      local.get 0
      i32.load offset=60
      i64.extend_i32_s
      local.get 3
      i32.load offset=8
      local.get 3
      i32.load
      call $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_
      local.get 0
      i32.load offset=500
      i64.const 4
      local.get 0
      i32.load offset=60
      i64.extend_i32_s
      local.get 3
      i32.load offset=8
      local.get 3
      i32.load
      call $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_
    end
    local.get 3
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $load_convolutional_weights_layer__char*__int*_ (type 15) (param i32 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 1
    i32.store offset=24
    local.get 3
    local.get 2
    i32.store offset=16
    local.get 3
    local.get 0
    i32.load offset=88
    local.get 0
    i32.load offset=112
    i32.div_s
    local.get 0
    i32.load offset=104
    i32.mul
    local.get 0
    i32.load offset=116
    i32.mul
    local.get 0
    i32.load offset=116
    i32.mul
    i32.store offset=12
    local.get 0
    i32.load offset=432
    i64.const 4
    local.get 0
    i32.load offset=104
    i64.extend_i32_s
    local.get 3
    i32.load offset=24
    local.get 3
    i32.load offset=16
    call $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_
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
      i64.const 4
      local.get 0
      i32.load offset=104
      i64.extend_i32_s
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=16
      call $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_
      local.get 0
      i32.load offset=496
      i64.const 4
      local.get 0
      i32.load offset=104
      i64.extend_i32_s
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=16
      call $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_
      local.get 0
      i32.load offset=500
      i64.const 4
      local.get 0
      i32.load offset=104
      i64.extend_i32_s
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=16
      call $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_
    end
    local.get 0
    i32.load offset=448
    i64.const 4
    local.get 3
    i32.load offset=12
    i64.extend_i32_s
    local.get 3
    i32.load offset=24
    local.get 3
    i32.load offset=16
    call $read_bytes_void*__unsigned_long__unsigned_long__char*__int*_
    block  ;; label = @1
      local.get 0
      i32.load offset=52
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=448
      local.get 0
      i32.load offset=88
      local.get 0
      i32.load offset=116
      i32.mul
      local.get 0
      i32.load offset=116
      i32.mul
      local.get 0
      i32.load offset=104
      call $transpose_matrix_float*__int__int_
    end
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $load_weights_network*__char*_ (type 18) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 3808
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=3800
    local.get 2
    local.get 1
    i32.store offset=3792
    local.get 2
    i32.const 0
    i32.store offset=3788
    local.get 2
    i32.const 0
    i32.store offset=3784
    local.get 2
    i32.const 0
    i32.store offset=3780
    local.get 2
    i32.const 0
    i32.store offset=3776
    local.get 2
    i32.const 0
    i32.store offset=3772
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        i32.load offset=3772
        local.get 2
        i32.load offset=3800
        i32.load
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
        i32.const 3016
        i32.add
        local.get 2
        i32.load offset=3800
        i32.load offset=24
        local.get 2
        i32.load offset=3772
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 752
        i32.mul
        i32.add
        i32.const 1160
        call $memcpy
        drop
        block  ;; label = @3
          block  ;; label = @4
            local.get 2
            i32.load offset=3356
            i32.eqz
            br_if 0 (;@4;)
            br 1 (;@3;)
          end
          block  ;; label = @4
            local.get 2
            i32.load offset=3016
            br_if 0 (;@4;)
            local.get 2
            i32.const 2264
            i32.add
            local.get 2
            i32.const 3016
            i32.add
            i32.const 1160
            call $memcpy
            drop
            local.get 2
            i32.load offset=3792
            local.set 1
            local.get 2
            i32.const 760
            i32.add
            local.get 2
            i32.const 2264
            i32.add
            i32.const 752
            call $memcpy
            drop
            local.get 2
            i32.const 760
            i32.add
            local.get 1
            local.get 2
            i32.const 3776
            i32.add
            call $load_convolutional_weights_layer__char*__int*_
          end
          block  ;; label = @4
            local.get 2
            i32.load offset=3016
            i32.const 2
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 2
            i32.const 1512
            i32.add
            local.get 2
            i32.const 3016
            i32.add
            i32.const 1160
            call $memcpy
            drop
            local.get 2
            i32.load offset=3792
            local.set 1
            local.get 2
            i32.const 8
            i32.add
            local.get 2
            i32.const 1512
            i32.add
            i32.const 752
            call $memcpy
            drop
            local.get 2
            i32.const 8
            i32.add
            local.get 1
            local.get 2
            i32.const 3776
            i32.add
            call $load_connected_weights_layer__char*__int*_
          end
        end
        local.get 2
        local.get 2
        i32.load offset=3772
        i32.const 1
        i32.add
        i32.store offset=3772
        br 0 (;@2;)
      end
    end
    local.get 2
    i32.const 3808
    i32.add
    global.set $__stack_pointer)
  (func $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_ (type 19) (param i32 i64 i64 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    local.get 5
    local.get 0
    i32.store offset=40
    local.get 5
    local.get 1
    i64.store offset=32
    local.get 5
    local.get 2
    i64.store offset=24
    local.get 5
    local.get 3
    i32.store offset=16
    local.get 5
    local.get 4
    i32.store offset=8
    local.get 5
    i32.load offset=16
    i32.load
    local.get 5
    i32.load offset=8
    i32.load
    i64.extend_i32_s
    local.get 5
    i64.load offset=32
    local.get 5
    i64.load offset=24
    i64.mul
    i64.add
    call $realloc
    local.set 4
    local.get 5
    i32.load offset=16
    local.get 4
    i32.store
    local.get 5
    i32.load offset=16
    i32.load
    local.get 5
    i32.load offset=8
    i32.load
    i64.extend_i32_s
    i32.wrap_i64
    i32.add
    local.get 5
    i32.load offset=40
    local.get 5
    i64.load offset=32
    local.get 5
    i64.load offset=24
    i64.mul
    i32.wrap_i64
    call $memcpy
    drop
    local.get 5
    i32.load offset=8
    local.tee 4
    local.get 4
    i32.load
    i64.extend_i32_s
    local.get 5
    i64.load offset=32
    local.get 5
    i64.load offset=24
    i64.mul
    i64.add
    i32.wrap_i64
    i32.store
    local.get 5
    i32.const 48
    i32.add
    global.set $__stack_pointer)
  (func $save_connected_weights_layer__char**__int*_ (type 15) (param i32 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 1
    i32.store offset=8
    local.get 3
    local.get 2
    i32.store
    local.get 0
    i32.load offset=432
    i64.const 4
    local.get 0
    i32.load offset=60
    i64.extend_i32_s
    local.get 3
    i32.load offset=8
    local.get 3
    i32.load
    call $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_
    local.get 0
    i32.load offset=448
    i64.const 4
    local.get 0
    i32.load offset=60
    local.get 0
    i32.load offset=56
    i32.mul
    i64.extend_i32_s
    local.get 3
    i32.load offset=8
    local.get 3
    i32.load
    call $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_
    block  ;; label = @1
      local.get 0
      i32.load offset=36
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=440
      i64.const 4
      local.get 0
      i32.load offset=60
      i64.extend_i32_s
      local.get 3
      i32.load offset=8
      local.get 3
      i32.load
      call $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_
      local.get 0
      i32.load offset=496
      i64.const 4
      local.get 0
      i32.load offset=60
      i64.extend_i32_s
      local.get 3
      i32.load offset=8
      local.get 3
      i32.load
      call $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_
      local.get 0
      i32.load offset=500
      i64.const 4
      local.get 0
      i32.load offset=60
      i64.extend_i32_s
      local.get 3
      i32.load offset=8
      local.get 3
      i32.load
      call $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_
    end
    local.get 3
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $save_convolutional_weights_layer__char**__int*_ (type 15) (param i32 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 1
    i32.store offset=24
    local.get 3
    local.get 2
    i32.store offset=16
    local.get 3
    local.get 0
    i32.load offset=64
    i32.store offset=12
    local.get 0
    i32.load offset=432
    i64.const 4
    local.get 0
    i32.load offset=104
    i64.extend_i32_s
    local.get 3
    i32.load offset=24
    local.get 3
    i32.load offset=16
    call $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_
    block  ;; label = @1
      local.get 0
      i32.load offset=36
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=440
      i64.const 4
      local.get 0
      i32.load offset=104
      i64.extend_i32_s
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=16
      call $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_
      local.get 0
      i32.load offset=496
      i64.const 4
      local.get 0
      i32.load offset=104
      i64.extend_i32_s
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=16
      call $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_
      local.get 0
      i32.load offset=500
      i64.const 4
      local.get 0
      i32.load offset=104
      i64.extend_i32_s
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=16
      call $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_
    end
    local.get 0
    i32.load offset=448
    i64.const 4
    local.get 3
    i32.load offset=12
    i64.extend_i32_s
    local.get 3
    i32.load offset=24
    local.get 3
    i32.load offset=16
    call $write_bytes_void*__unsigned_long__unsigned_long__char**__int*_
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $save_weights_network*_ (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 3792
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=3784
    local.get 1
    i32.const 0
    i32.store offset=3776
    local.get 1
    i32.const 0
    i32.store offset=3772
    local.get 1
    i32.const 0
    i32.store offset=3768
    block  ;; label = @1
      loop  ;; label = @2
        local.get 1
        i32.load offset=3768
        local.get 1
        i32.load offset=3784
        i32.load
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 1
        i32.const 3016
        i32.add
        local.get 1
        i32.load offset=3784
        i32.load offset=24
        local.get 1
        i32.load offset=3768
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 752
        i32.mul
        i32.add
        i32.const 1160
        call $memcpy
        drop
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.load offset=3360
            i32.eqz
            br_if 0 (;@4;)
            br 1 (;@3;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=3016
            br_if 0 (;@4;)
            local.get 1
            i32.const 2264
            i32.add
            local.get 1
            i32.const 3016
            i32.add
            i32.const 1160
            call $memcpy
            drop
            local.get 1
            i32.const 760
            i32.add
            local.get 1
            i32.const 2264
            i32.add
            i32.const 752
            call $memcpy
            drop
            local.get 1
            i32.const 760
            i32.add
            local.get 1
            i32.const 3776
            i32.add
            local.get 1
            i32.const 3772
            i32.add
            call $save_convolutional_weights_layer__char**__int*_
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=3016
            i32.const 2
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1512
            i32.add
            local.get 1
            i32.const 3016
            i32.add
            i32.const 1160
            call $memcpy
            drop
            local.get 1
            i32.const 8
            i32.add
            local.get 1
            i32.const 1512
            i32.add
            i32.const 752
            call $memcpy
            drop
            local.get 1
            i32.const 8
            i32.add
            local.get 1
            i32.const 3776
            i32.add
            local.get 1
            i32.const 3772
            i32.add
            call $save_connected_weights_layer__char**__int*_
          end
        end
        local.get 1
        local.get 1
        i32.load offset=3768
        i32.const 1
        i32.add
        i32.store offset=3768
        br 0 (;@2;)
      end
    end
    local.get 1
    i32.load offset=3776
    i64.const 1
    local.get 1
    i32.load offset=3772
    i64.extend_i32_s
    call $ocall_push_weights
    drop
    local.get 1
    i32.const 3792
    i32.add
    global.set $__stack_pointer)
  (func $network_predict_data_network*__data_ (type 15) (param i32 i32 i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 80
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 1
    i32.store offset=56
    local.get 3
    local.get 3
    i32.load offset=56
    i32.load offset=108
    i32.store offset=40
    local.get 3
    i32.const 8
    i32.add
    local.get 2
    i32.load offset=8
    local.get 3
    i32.load offset=40
    call $make_matrix
    local.get 3
    i32.load offset=16
    local.set 1
    local.get 3
    local.get 3
    i64.load offset=8
    i64.store offset=64
    local.get 3
    local.get 1
    i32.store offset=72
    local.get 3
    local.get 3
    i32.load offset=56
    i32.load offset=4
    local.get 2
    i32.load offset=12
    i32.mul
    i64.extend_i32_s
    i64.const 4
    call $calloc
    i32.store offset=32
    local.get 3
    i32.const 0
    i32.store offset=52
    block  ;; label = @1
      loop  ;; label = @2
        local.get 3
        i32.load offset=52
        local.get 2
        i32.load offset=8
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 3
        i32.const 0
        i32.store offset=44
        block  ;; label = @3
          block  ;; label = @4
            loop  ;; label = @5
              local.get 3
              i32.load offset=44
              local.get 3
              i32.load offset=56
              i32.load offset=4
              i32.lt_s
              i32.const 1
              i32.and
              i32.eqz
              br_if 1 (;@4;)
              block  ;; label = @6
                local.get 3
                i32.load offset=52
                local.get 3
                i32.load offset=44
                i32.add
                local.get 2
                i32.load offset=8
                i32.eq
                i32.const 1
                i32.and
                i32.eqz
                br_if 0 (;@6;)
                br 3 (;@3;)
              end
              local.get 3
              i32.load offset=32
              local.get 3
              i32.load offset=44
              local.get 2
              i32.load offset=12
              i32.mul
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              local.get 2
              i32.load offset=16
              local.get 3
              i32.load offset=52
              local.get 3
              i32.load offset=44
              i32.add
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              i32.load
              local.get 2
              i32.load offset=12
              i64.extend_i32_s
              i64.const 2
              i64.shl
              i32.wrap_i64
              call $memcpy
              drop
              local.get 3
              local.get 3
              i32.load offset=44
              i32.const 1
              i32.add
              i32.store offset=44
              br 0 (;@5;)
            end
          end
        end
        local.get 3
        local.get 3
        i32.load offset=56
        local.get 3
        i32.load offset=32
        call $network_predict
        i32.store offset=24
        local.get 3
        i32.const 0
        i32.store offset=44
        block  ;; label = @3
          block  ;; label = @4
            loop  ;; label = @5
              local.get 3
              i32.load offset=44
              local.get 3
              i32.load offset=56
              i32.load offset=4
              i32.lt_s
              i32.const 1
              i32.and
              i32.eqz
              br_if 1 (;@4;)
              block  ;; label = @6
                local.get 3
                i32.load offset=52
                local.get 3
                i32.load offset=44
                i32.add
                local.get 2
                i32.load offset=8
                i32.eq
                i32.const 1
                i32.and
                i32.eqz
                br_if 0 (;@6;)
                br 3 (;@3;)
              end
              local.get 3
              i32.const 0
              i32.store offset=48
              block  ;; label = @6
                loop  ;; label = @7
                  local.get 3
                  i32.load offset=48
                  local.get 3
                  i32.load offset=40
                  i32.lt_s
                  i32.const 1
                  i32.and
                  i32.eqz
                  br_if 1 (;@6;)
                  local.get 3
                  i32.load offset=72
                  local.get 3
                  i32.load offset=52
                  local.get 3
                  i32.load offset=44
                  i32.add
                  i64.extend_i32_s
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  local.get 3
                  i32.load offset=48
                  i64.extend_i32_s
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  local.get 3
                  i32.load offset=24
                  local.get 3
                  i32.load offset=48
                  local.get 3
                  i32.load offset=44
                  local.get 3
                  i32.load offset=40
                  i32.mul
                  i32.add
                  i64.extend_i32_s
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  f32.load
                  f32.store
                  local.get 3
                  local.get 3
                  i32.load offset=48
                  i32.const 1
                  i32.add
                  i32.store offset=48
                  br 0 (;@7;)
                end
              end
              local.get 3
              local.get 3
              i32.load offset=44
              i32.const 1
              i32.add
              i32.store offset=44
              br 0 (;@5;)
            end
          end
        end
        local.get 3
        local.get 3
        i32.load offset=52
        local.get 3
        i32.load offset=56
        i32.load offset=4
        i32.add
        i32.store offset=52
        br 0 (;@2;)
      end
    end
    local.get 3
    i32.load offset=32
    call $free
    local.get 3
    i64.load offset=64
    local.set 4
    local.get 0
    local.get 3
    i32.load offset=72
    i32.store offset=8
    local.get 0
    local.get 4
    i64.store
    local.get 3
    i32.const 80
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
