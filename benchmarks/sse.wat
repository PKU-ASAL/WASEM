(module
  (type (;0;) (func (param i32 i64) (result i32)))
  (type (;1;) (func (param i64) (result i32)))
  (type (;2;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;3;) (func (param i32)))
  (type (;4;) (func (param i32 i32) (result i32)))
  (type (;5;) (func))
  (type (;6;) (func (param i32) (result i64)))
  (type (;7;) (func (param i32 i32 i32) (result i32)))
  (type (;8;) (func (param i32 i32 i64)))
  (type (;9;) (func (param i32 i32 i32 i32)))
  (type (;10;) (func (param i32 i32)))
  (type (;11;) (func (param i32 i32 i64) (result i32)))
  (type (;12;) (func (param i32 i64)))
  (type (;13;) (func (param i32) (result i32)))
  (type (;14;) (func (param i32 i32 i32)))
  (type (;15;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;16;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;17;) (func (param i32 i64 i32 i64)))
  (type (;18;) (func (param i32 i64 i32 i64 i32 i64)))
  (type (;19;) (func (param i32 i64 i32 i64 i32 i64 i32 i64 i32 i64)))
  (type (;20;) (func (param i32 i32 i64 i64 i32 i64) (result i32)))
  (type (;21;) (func (param i32 i64 i64) (result i32)))
  (type (;22;) (func (param i32 i32 i64 i32)))
  (type (;23;) (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;24;) (func (param i32 i32 i32 i64)))
  (type (;25;) (func (param i32 i32 i64 i32 i64)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "malloc" (func $malloc (type 1)))
  (import "env" "memcpy_s" (func $memcpy_s (type 2)))
  (import "env" "free" (func $free (type 3)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 1)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 4)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 5)))
  (import "env" "strlen" (func $strlen (type 6)))
  (import "env" "memset" (func $memset (type 7)))
  (import "env" "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm" (func $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_ (type 8)))
  (import "env" "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev" (func $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__ (type 3)))
  (import "env" "__cxa_atexit" (func $__cxa_atexit (type 7)))
  (import "env" "memcpy" (func $memcpy (type 7)))
  (import "env" "__assert" (func $__assert (type 9)))
  (import "env" "_ZNSt3__19to_stringEi" (func $std::__1::to_string_int_ (type 10)))
  (import "env" "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm" (func $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::append_char_const*__unsigned_long_ (type 11)))
  (import "env" "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm" (func $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::insert_unsigned_long__char_const*__unsigned_long_ (type 2)))
  (import "env" "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7reserveEm" (func $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::reserve_unsigned_long_ (type 12)))
  (import "env" "_ZdlPv" (func $operator_delete_void*_ (type 3)))
  (import "env" "__stack_chk_fail" (func $__stack_chk_fail (type 5)))
  (import "env" "__cxa_begin_catch" (func $__cxa_begin_catch (type 13)))
  (import "env" "_ZSt9terminatev" (func $std::terminate__ (type 5)))
  (import "env" "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_" (func $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::basic_string_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&_ (type 10)))
  (import "env" "memcmp" (func $memcmp (type 11)))
  (import "env" "_ZNKSt3__120__vector_base_commonILb1EE20__throw_length_errorEv" (func $std::__1::__vector_base_common<true>::__throw_length_error___const (type 3)))
  (import "env" "_Znwm" (func $operator_new_unsigned_long_ (type 1)))
  (import "env" "__cxa_allocate_exception" (func $__cxa_allocate_exception (type 1)))
  (import "env" "_ZNSt9bad_allocC1Ev" (func $std::bad_alloc::bad_alloc__ (type 3)))
  (import "env" "_ZNSt9bad_allocD1Ev" (func $std::bad_alloc::~bad_alloc__ (type 3)))
  (import "env" "__cxa_throw" (func $__cxa_throw (type 14)))
  (import "env" "vsnprintf" (func $vsnprintf (type 15)))
  (import "env" "strtok" (func $strtok (type 4)))
  (import "env" "sgx_rijndael128GCM_encrypt" (func $sgx_rijndael128GCM_encrypt (type 16)))
  (import "env" "sgx_rijndael128GCM_decrypt" (func $sgx_rijndael128GCM_decrypt (type 16)))
  (import "env" "realloc" (func $realloc (type 0)))
  (func $__wasm_call_ctors (type 5)
    call $_GLOBAL__sub_I_CryptoEnclave.cpp
    call $_GLOBAL__sub_I_EnclaveUtils.cpp)
  (func $sgx_ecall_init (type 13) (param i32) (result i32)
    (local i32 i64 i32 i64 i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 32
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=24
      local.set 2
      local.get 0
      i32.load offset=16
      local.set 3
      local.get 0
      i64.load offset=8
      local.set 4
      block  ;; label = @2
        local.get 0
        i32.load
        local.tee 5
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        local.get 4
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        local.get 2
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 6
      i32.const 0
      local.set 0
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 5
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            local.set 0
            local.get 4
            i64.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 4
              call $malloc
              local.tee 0
              br_if 0 (;@5;)
              i32.const 3
              return
            end
            local.get 0
            local.get 4
            local.get 5
            local.get 4
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 1
            i32.const 0
            local.set 6
            br 1 (;@3;)
          end
          block  ;; label = @4
            block  ;; label = @5
              local.get 3
              i32.eqz
              br_if 0 (;@5;)
              local.get 2
              i64.eqz
              br_if 0 (;@5;)
              block  ;; label = @6
                local.get 2
                call $malloc
                local.tee 6
                br_if 0 (;@6;)
                i32.const 0
                local.set 6
                i32.const 3
                local.set 1
                br 2 (;@4;)
              end
              i32.const 1
              local.set 1
              local.get 6
              local.get 2
              local.get 3
              local.get 2
              call $memcpy_s
              br_if 1 (;@4;)
            end
            local.get 0
            local.get 4
            local.get 6
            local.get 2
            call $ecall_init
            i32.const 0
            local.set 1
          end
          local.get 0
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 0
        call $free
      end
      local.get 6
      i32.eqz
      br_if 0 (;@1;)
      local.get 6
      call $free
    end
    local.get 1)
  (func $ecall_init (type 17) (param i32 i64 i32 i64)
    i32.const 1312
    local.get 0
    local.get 1
    i32.wrap_i64
    call $memcpy
    drop
    i32.const 1328
    local.get 2
    local.get 3
    i32.wrap_i64
    call $memcpy
    drop)
  (func $sgx_ecall_query_keyword (type 13) (param i32) (result i32)
    (local i32 i64 i32 i64 i32 i64 i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 48
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=40
      local.set 2
      local.get 0
      i32.load offset=32
      local.set 3
      local.get 0
      i64.load offset=24
      local.set 4
      local.get 0
      i32.load offset=16
      local.set 5
      local.get 0
      i64.load offset=8
      local.set 6
      block  ;; label = @2
        local.get 0
        i32.load
        local.tee 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 6
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 5
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        local.get 4
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        local.get 2
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 7
      i32.const 0
      local.set 8
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            local.set 8
            local.get 6
            i64.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 6
              call $malloc
              local.tee 8
              br_if 0 (;@5;)
              i32.const 3
              return
            end
            local.get 8
            local.get 6
            local.get 0
            local.get 6
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 1
            i32.const 0
            local.set 0
            i32.const 0
            local.set 7
            br 1 (;@3;)
          end
          block  ;; label = @4
            block  ;; label = @5
              local.get 5
              i32.eqz
              br_if 0 (;@5;)
              local.get 4
              i64.eqz
              br_if 0 (;@5;)
              i32.const 2
              local.set 1
              i32.const 0
              local.set 0
              block  ;; label = @6
                local.get 4
                i64.const 3
                i64.and
                i64.const 0
                i64.eq
                br_if 0 (;@6;)
                i32.const 0
                local.set 7
                br 2 (;@4;)
              end
              block  ;; label = @6
                local.get 4
                call $malloc
                local.tee 7
                br_if 0 (;@6;)
                i32.const 3
                local.set 1
                i32.const 0
                local.set 7
                br 2 (;@4;)
              end
              i32.const 1
              local.set 1
              local.get 7
              local.get 4
              local.get 5
              local.get 4
              call $memcpy_s
              br_if 1 (;@4;)
            end
            i32.const 0
            local.set 1
            i32.const 0
            local.set 0
            block  ;; label = @5
              local.get 3
              i32.eqz
              br_if 0 (;@5;)
              i32.const 0
              local.set 0
              local.get 2
              i64.eqz
              br_if 0 (;@5;)
              i32.const 0
              local.set 0
              block  ;; label = @6
                local.get 2
                i64.const 3
                i64.and
                i64.const 0
                i64.eq
                br_if 0 (;@6;)
                i32.const 2
                local.set 1
                br 2 (;@4;)
              end
              block  ;; label = @6
                local.get 2
                call $malloc
                local.tee 0
                br_if 0 (;@6;)
                i32.const 3
                local.set 1
                i32.const 0
                local.set 0
                br 2 (;@4;)
              end
              local.get 0
              local.get 2
              local.get 3
              local.get 2
              call $memcpy_s
              i32.eqz
              br_if 0 (;@5;)
              i32.const 1
              local.set 1
              br 1 (;@4;)
            end
            local.get 8
            local.get 6
            local.get 7
            local.get 4
            local.get 0
            local.get 2
            call $ecall_query_keyword
          end
          local.get 8
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 8
        call $free
      end
      block  ;; label = @2
        local.get 7
        i32.eqz
        br_if 0 (;@2;)
        local.get 7
        call $free
      end
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      call $free
    end
    local.get 1)
  (func $ecall_query_keyword (type 18) (param i32 i64 i32 i64 i32 i64)
    (local i32 i32 i32 i32 i32 i64 i32 i32 i32 i32 i32 i64 i32 i32 i32 i64 i32 i32 i32 i64 i32 i32 i64 i32 i64 i32 i32 i32 i64)
    global.get $__stack_pointer
    i32.const 10500224
    i32.sub
    local.tee 6
    global.set $__stack_pointer
    local.get 6
    i32.const 0
    i32.load
    i32.store offset=10500220
    local.get 4
    i32.load
    local.set 7
    i64.const 9360000
    call $malloc
    local.set 8
    i64.const 9360000
    call $malloc
    local.set 9
    i64.const 9360000
    call $malloc
    local.set 10
    i64.const 0
    local.set 11
    local.get 6
    i32.const 4500112
    i32.add
    i32.const 16
    i32.add
    i64.const 0
    i64.store
    local.get 6
    i32.const 4500112
    i32.add
    i32.const 8
    i32.add
    i64.const 0
    i64.store
    local.get 6
    i64.const 0
    i64.store offset=4500112
    local.get 7
    i32.const 130000
    i32.div_s
    local.set 12
    block  ;; label = @1
      local.get 1
      i64.eqz
      local.get 0
      i32.const 0
      i32.ne
      i32.or
      local.tee 13
      br_if 0 (;@1;)
      i32.const 1187
      i32.const 2085
      i32.const 1174
      i32.const 1107
      call $__assert
    end
    local.get 6
    i32.const 4500112
    i32.add
    local.get 0
    local.get 1
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_
    local.get 6
    i32.const 112
    i32.add
    local.get 2
    i32.load
    call $std::__1::to_string_int_
    local.get 6
    i32.const 10500120
    i32.add
    i32.const 16
    i32.add
    local.get 6
    i32.const 4500112
    i32.add
    local.get 6
    i32.load offset=128
    local.get 6
    i32.const 112
    i32.add
    i32.const 1
    i32.or
    local.get 6
    i32.load8_u offset=112
    local.tee 14
    i32.const 1
    i32.and
    local.tee 15
    select
    local.get 6
    i64.load offset=120
    local.get 14
    i32.const 1
    i32.shr_u
    i64.extend_i32_u
    local.get 15
    select
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::append_char_const*__unsigned_long_
    local.tee 14
    i32.const 16
    i32.add
    local.tee 15
    i64.load
    i64.store
    local.get 6
    i32.const 10500120
    i32.add
    i32.const 8
    i32.add
    local.get 14
    i32.const 8
    i32.add
    local.tee 16
    i64.load
    i64.store
    local.get 6
    local.get 14
    i64.load
    i64.store offset=10500120
    local.get 14
    i64.const 0
    i64.store
    local.get 16
    i64.const 0
    i64.store
    local.get 15
    i64.const 0
    i64.store
    local.get 6
    i32.const 112
    i32.add
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
    local.get 6
    i32.const 4500112
    i32.add
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
    local.get 6
    i32.const 4500112
    i32.add
    i32.const 0
    i32.const 6000000
    call $memset
    drop
    local.get 6
    i32.const 112
    i32.add
    i32.const 0
    i32.const 4500000
    call $memset
    drop
    i64.const 0
    local.set 17
    block  ;; label = @1
      local.get 7
      i32.const -129999
      i32.lt_s
      br_if 0 (;@1;)
      local.get 6
      i32.const 10500144
      i32.add
      i32.const 8
      i32.add
      local.set 18
      local.get 6
      i32.const 10500144
      i32.add
      i32.const 1
      i32.or
      local.set 19
      local.get 6
      i32.const 10500120
      i32.add
      i32.const 1
      i32.or
      local.set 20
      local.get 12
      i32.const 1
      i32.add
      i64.extend_i32_u
      local.set 21
      local.get 6
      i32.const 112
      i32.add
      i32.const 8
      i32.or
      local.set 22
      local.get 6
      i32.const 4500112
      i32.add
      i32.const 8
      i32.or
      local.set 23
      local.get 6
      i32.const 88
      i32.add
      i32.const 16
      i32.add
      local.set 14
      i32.const 1
      local.set 24
      i64.const 0
      local.set 25
      i32.const 0
      local.set 26
      i64.const 0
      local.set 17
      i64.const 0
      local.set 11
      loop  ;; label = @2
        local.get 6
        i64.const 0
        i64.store offset=48
        local.get 6
        i64.const 0
        i64.store offset=24
        local.get 4
        i32.load
        local.tee 7
        local.get 25
        i32.wrap_i64
        local.tee 15
        i32.const -130000
        i32.mul
        i32.add
        local.set 27
        block  ;; label = @3
          local.get 15
          i32.const 130000
          i32.mul
          i32.const 1
          i32.or
          local.get 7
          local.get 25
          i64.const 1
          i64.add
          local.tee 28
          i64.const 130000
          i64.mul
          local.tee 25
          i32.wrap_i64
          local.get 25
          local.get 7
          i64.extend_i32_s
          i64.gt_s
          local.tee 29
          select
          local.tee 7
          i32.gt_s
          br_if 0 (;@3;)
          local.get 26
          i64.extend_i32_s
          local.set 25
          local.get 7
          i64.extend_i32_s
          local.set 30
          local.get 24
          local.set 15
          local.get 8
          local.set 16
          loop  ;; label = @4
            local.get 6
            i32.const 88
            i32.add
            local.get 15
            call $std::__1::to_string_int_
            local.get 6
            i32.const 10500144
            i32.add
            i32.const 16
            i32.add
            local.tee 12
            local.get 6
            i32.const 88
            i32.add
            i64.const 0
            local.get 6
            i32.load offset=10500136
            local.get 20
            local.get 6
            i32.load8_u offset=10500120
            local.tee 7
            i32.const 1
            i32.and
            local.tee 31
            select
            local.get 6
            i64.load offset=10500128
            local.get 7
            i32.const 1
            i32.shr_u
            i64.extend_i32_u
            local.get 31
            select
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::insert_unsigned_long__char_const*__unsigned_long_
            local.tee 7
            i32.const 16
            i32.add
            local.tee 31
            i64.load
            i64.store
            local.get 6
            i32.const 10500144
            i32.add
            i32.const 8
            i32.add
            local.tee 32
            local.get 7
            i32.const 8
            i32.add
            local.tee 33
            i64.load
            i64.store
            local.get 6
            local.get 7
            i64.load
            i64.store offset=10500144
            local.get 7
            i64.const 0
            i64.store
            local.get 33
            i64.const 0
            i64.store
            local.get 31
            i64.const 0
            i64.store
            local.get 6
            i32.const 88
            i32.add
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            i32.const 1312
            local.get 12
            i32.load
            local.get 19
            local.get 6
            i32.load8_u offset=10500144
            local.tee 7
            i32.const 1
            i32.and
            local.tee 12
            select
            local.get 32
            i64.load
            local.get 7
            i32.const 1
            i32.shr_u
            i64.extend_i32_u
            local.get 12
            select
            i64.const 1
            i64.add
            local.get 16
            call $prf_F_improve_void_const*__void_const*__unsigned_long__rand_t*_
            local.get 16
            i32.const 72
            i32.add
            local.set 16
            local.get 15
            i32.const 1
            i32.add
            local.set 15
            local.get 6
            i32.const 10500144
            i32.add
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            local.get 25
            i64.const 1
            i64.add
            local.tee 25
            local.get 30
            i64.lt_s
            br_if 0 (;@4;)
          end
        end
        local.get 8
        local.get 9
        local.get 27
        i64.extend_i32_s
        i64.const 130000
        local.get 29
        select
        local.tee 25
        i64.const 72
        local.get 6
        i32.const 48
        i32.add
        i64.const 8
        call $ocall_get_docId
        drop
        local.get 8
        local.get 10
        local.get 25
        i64.const 72
        local.get 6
        i32.const 24
        i32.add
        i64.const 8
        call $ocall_get_delId
        drop
        block  ;; label = @3
          local.get 6
          i64.load offset=48
          local.tee 30
          i64.const 0
          i64.le_s
          br_if 0 (;@3;)
          local.get 23
          local.get 17
          i32.wrap_i64
          i32.const 24
          i32.mul
          i32.add
          local.set 15
          i64.const 0
          local.set 25
          local.get 9
          local.set 16
          loop  ;; label = @4
            i32.const 1328
            local.get 16
            i32.const 8
            i32.add
            local.get 16
            i64.load
            local.get 6
            i32.const 10500144
            i32.add
            call $prf_Dec_improve_void_const*__void_const*__unsigned_long__rand_t*_
            local.get 6
            i32.const 88
            i32.add
            i32.const 8
            i32.add
            local.tee 12
            i64.const 0
            i64.store
            local.get 14
            i64.const 0
            i64.store
            local.get 6
            i64.const 0
            i64.store offset=88
            local.get 6
            i32.const 88
            i32.add
            local.get 18
            local.get 6
            i64.load offset=10500144
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_
            block  ;; label = @5
              block  ;; label = @6
                local.get 15
                i32.const -8
                i32.add
                local.tee 7
                i32.load8_u
                i32.const 1
                i32.and
                i32.eqz
                br_if 0 (;@6;)
                local.get 15
                i32.const 8
                i32.add
                i32.load
                i32.const 0
                i32.store8
                local.get 15
                i64.const 0
                i64.store
                br 1 (;@5;)
              end
              local.get 7
              i32.const 0
              i32.store8
              local.get 15
              i32.const -7
              i32.add
              i32.const 0
              i32.store8
            end
            local.get 7
            i64.const 0
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::reserve_unsigned_long_
            local.get 7
            i32.const 16
            i32.add
            local.get 14
            i64.load
            i64.store
            local.get 7
            i32.const 8
            i32.add
            local.get 12
            i64.load
            i64.store
            local.get 7
            local.get 6
            i64.load offset=88
            i64.store
            local.get 12
            i64.const 0
            i64.store
            local.get 14
            i64.const 0
            i64.store
            local.get 6
            i64.const 0
            i64.store offset=88
            local.get 16
            i32.const 72
            i32.add
            local.set 16
            local.get 15
            i32.const 24
            i32.add
            local.set 15
            local.get 6
            i32.const 88
            i32.add
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            local.get 6
            i64.load offset=48
            local.tee 30
            local.get 25
            i64.const 1
            i64.add
            local.tee 25
            i64.gt_s
            br_if 0 (;@4;)
          end
        end
        block  ;; label = @3
          local.get 6
          i64.load offset=24
          local.tee 34
          i64.const 1
          i64.lt_s
          br_if 0 (;@3;)
          local.get 22
          local.get 11
          i32.wrap_i64
          i32.const 24
          i32.mul
          i32.add
          local.set 15
          i64.const 0
          local.set 25
          local.get 10
          local.set 16
          loop  ;; label = @4
            i32.const 1328
            local.get 16
            i32.const 8
            i32.add
            local.get 16
            i64.load
            local.get 6
            i32.const 10500144
            i32.add
            call $prf_Dec_improve_void_const*__void_const*__unsigned_long__rand_t*_
            local.get 6
            i32.const 88
            i32.add
            i32.const 8
            i32.add
            local.tee 12
            i64.const 0
            i64.store
            local.get 14
            i64.const 0
            i64.store
            local.get 6
            i64.const 0
            i64.store offset=88
            local.get 6
            i32.const 88
            i32.add
            local.get 18
            local.get 6
            i64.load offset=10500144
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_
            block  ;; label = @5
              block  ;; label = @6
                local.get 15
                i32.const -8
                i32.add
                local.tee 7
                i32.load8_u
                i32.const 1
                i32.and
                i32.eqz
                br_if 0 (;@6;)
                local.get 15
                i32.const 8
                i32.add
                i32.load
                i32.const 0
                i32.store8
                local.get 15
                i64.const 0
                i64.store
                br 1 (;@5;)
              end
              local.get 7
              i32.const 0
              i32.store8
              local.get 15
              i32.const -7
              i32.add
              i32.const 0
              i32.store8
            end
            local.get 7
            i64.const 0
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::reserve_unsigned_long_
            local.get 7
            i32.const 16
            i32.add
            local.get 14
            i64.load
            i64.store
            local.get 7
            i32.const 8
            i32.add
            local.get 12
            i64.load
            i64.store
            local.get 7
            local.get 6
            i64.load offset=88
            i64.store
            local.get 12
            i64.const 0
            i64.store
            local.get 14
            i64.const 0
            i64.store
            local.get 6
            i64.const 0
            i64.store offset=88
            local.get 16
            i32.const 72
            i32.add
            local.set 16
            local.get 15
            i32.const 24
            i32.add
            local.set 15
            local.get 6
            i32.const 88
            i32.add
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            local.get 6
            i64.load offset=24
            local.tee 34
            local.get 25
            i64.const 1
            i64.add
            local.tee 25
            i64.gt_s
            br_if 0 (;@4;)
          end
        end
        local.get 30
        local.get 17
        i64.add
        local.set 17
        local.get 24
        i32.const 130000
        i32.add
        local.set 24
        local.get 26
        i32.const 130000
        i32.add
        local.set 26
        local.get 34
        local.get 11
        i64.add
        local.set 11
        local.get 28
        local.set 25
        local.get 28
        local.get 21
        i64.ne
        br_if 0 (;@2;)
      end
    end
    local.get 8
    call $free
    local.get 9
    call $free
    local.get 10
    call $free
    local.get 6
    i32.const 72
    i32.add
    i32.const 16
    i32.add
    i64.const 0
    i64.store
    local.get 6
    i32.const 72
    i32.add
    i32.const 8
    i32.add
    i64.const 0
    i64.store
    local.get 6
    i64.const 0
    i64.store offset=72
    local.get 6
    i32.const 4500112
    i32.add
    local.get 6
    i32.const 4500112
    i32.add
    local.get 17
    i32.wrap_i64
    i32.const 24
    i32.mul
    i32.add
    local.get 6
    i32.const 112
    i32.add
    local.get 6
    i32.const 112
    i32.add
    local.get 11
    i32.wrap_i64
    i32.const 24
    i32.mul
    i32.add
    local.get 6
    i32.const 72
    i32.add
    local.get 6
    i32.const 10500144
    i32.add
    call $std::__1::back_insert_iterator<std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>_>_std::__1::__set_difference<std::__1::__less<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>&__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::back_insert_iterator<std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>_>_>_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::back_insert_iterator<std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>_>__std::__1::__less<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>&_
    drop
    local.get 6
    i32.load offset=76
    local.tee 18
    i64.extend_i32_u
    local.get 6
    i32.load offset=72
    local.tee 14
    i64.extend_i32_u
    i64.sub
    local.tee 25
    i64.const 24
    i64.div_s
    i64.const 72
    i64.mul
    call $malloc
    local.set 33
    i64.const 0
    local.set 30
    block  ;; label = @1
      local.get 25
      i64.eqz
      br_if 0 (;@1;)
      i64.const 0
      local.set 25
      i32.const 0
      local.set 7
      local.get 33
      local.set 15
      loop  ;; label = @2
        local.get 15
        local.get 14
        local.get 7
        i32.add
        local.tee 16
        i32.const 8
        i32.add
        i64.load
        local.get 16
        i32.load8_u
        local.tee 16
        i32.const 1
        i32.shr_u
        i64.extend_i32_u
        local.get 16
        i32.const 1
        i32.and
        select
        i64.store
        block  ;; label = @3
          local.get 18
          i64.extend_i32_u
          local.tee 30
          local.get 14
          i64.extend_i32_u
          i64.sub
          i64.const 24
          i64.div_s
          local.tee 34
          local.get 25
          i64.gt_u
          br_if 0 (;@3;)
          i32.const 1134
          i32.const 1498
          i32.const 1227
          i32.const 1249
          call $__assert
          local.get 6
          i32.load offset=76
          local.tee 18
          i64.extend_i32_u
          local.tee 30
          local.get 6
          i32.load offset=72
          local.tee 14
          i64.extend_i32_u
          i64.sub
          i64.const 24
          i64.div_s
          local.set 34
        end
        local.get 15
        i32.const 8
        i32.add
        local.set 31
        local.get 14
        local.get 7
        i32.add
        local.tee 16
        i32.const 16
        i32.add
        i32.load
        local.get 16
        i32.const 1
        i32.add
        local.get 16
        i32.load8_u
        local.tee 16
        i32.const 1
        i32.and
        local.tee 12
        select
        local.set 32
        block  ;; label = @3
          local.get 34
          local.get 25
          i64.gt_u
          br_if 0 (;@3;)
          i32.const 1134
          i32.const 1498
          i32.const 1227
          i32.const 1249
          call $__assert
          local.get 6
          i32.load offset=72
          local.tee 14
          local.get 7
          i32.add
          i32.load8_u
          local.tee 16
          i32.const 1
          i32.and
          local.set 12
          local.get 6
          i32.load offset=76
          local.tee 18
          i64.extend_i32_u
          local.set 30
        end
        local.get 31
        local.get 32
        local.get 14
        local.get 7
        i32.add
        i32.const 8
        i32.add
        i64.load
        local.get 16
        i32.const 1
        i32.shr_u
        i64.extend_i32_u
        local.get 12
        select
        i32.wrap_i64
        call $memcpy
        drop
        local.get 15
        i32.const 72
        i32.add
        local.set 15
        local.get 7
        i32.const 24
        i32.add
        local.set 7
        local.get 30
        local.get 14
        i64.extend_i32_u
        i64.sub
        i64.const 24
        i64.div_s
        local.tee 30
        local.get 25
        i64.const 1
        i64.add
        local.tee 25
        i64.gt_u
        br_if 0 (;@2;)
      end
    end
    local.get 33
    local.get 30
    i64.const 72
    call $ocall_send_to_client
    drop
    local.get 33
    call $free
    i64.const 9360000
    call $malloc
    local.set 32
    i64.const 9360000
    call $malloc
    local.set 33
    local.get 4
    i32.const 1
    i32.store
    local.get 2
    local.get 2
    i32.load
    i32.const 1
    i32.add
    i32.store
    local.get 6
    i64.load32_u offset=76
    local.get 6
    i64.load32_u offset=72
    i64.sub
    i64.const 24
    i64.div_s
    i64.const 130000
    i64.div_u
    i32.wrap_i64
    local.tee 14
    i32.const -1
    local.get 14
    i32.const -1
    i32.gt_s
    select
    i32.const 1
    i32.add
    i64.extend_i32_u
    local.set 17
    local.get 6
    i32.const 10500144
    i32.add
    i32.const 1
    i32.or
    local.set 20
    local.get 6
    i32.const 1
    i32.or
    local.set 8
    local.get 6
    i32.const 24
    i32.add
    i32.const 1
    i32.or
    local.set 24
    i32.const 0
    local.set 29
    local.get 6
    i32.const 48
    i32.add
    i32.const 16
    i32.add
    local.set 26
    local.get 6
    i32.const 48
    i32.add
    i32.const 8
    i32.add
    local.set 27
    i32.const 0
    local.set 9
    i64.const 0
    local.set 28
    i32.const 0
    local.set 10
    block  ;; label = @1
      loop  ;; label = @2
        block  ;; label = @3
          local.get 28
          local.get 17
          i64.ne
          br_if 0 (;@3;)
          local.get 32
          call $free
          local.get 33
          call $free
          block  ;; label = @4
            local.get 6
            i32.load offset=72
            local.tee 7
            i32.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 6
              i32.load offset=76
              local.tee 14
              local.get 7
              i32.eq
              br_if 0 (;@5;)
              loop  ;; label = @6
                local.get 6
                local.get 14
                i32.const -24
                i32.add
                local.tee 14
                i32.store offset=76
                local.get 14
                call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
                local.get 6
                i32.load offset=76
                local.tee 14
                local.get 7
                i32.ne
                br_if 0 (;@6;)
              end
              local.get 6
              i32.load offset=72
              local.set 7
            end
            local.get 7
            call $operator_delete_void*_
          end
          i32.const 4499976
          local.set 14
          loop  ;; label = @4
            local.get 6
            i32.const 112
            i32.add
            local.get 14
            i32.add
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            local.get 14
            i32.const -24
            i32.add
            local.tee 14
            i32.const -24
            i32.ne
            br_if 0 (;@4;)
          end
          i32.const 5999976
          local.set 14
          loop  ;; label = @4
            local.get 6
            i32.const 4500112
            i32.add
            local.get 14
            i32.add
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            local.get 14
            i32.const -24
            i32.add
            local.tee 14
            i32.const -24
            i32.ne
            br_if 0 (;@4;)
          end
          local.get 6
          i32.const 10500120
          i32.add
          call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
          i32.const 0
          i32.load
          local.get 6
          i32.load offset=10500220
          i32.eq
          br_if 2 (;@1;)
          call $__stack_chk_fail
          unreachable
        end
        local.get 6
        i64.load32_u offset=76
        local.get 6
        i64.load32_u offset=72
        i64.sub
        i64.const 24
        i64.div_s
        local.tee 25
        local.get 28
        i32.wrap_i64
        i32.const 130000
        i32.mul
        local.tee 14
        i64.extend_i32_u
        i64.sub
        local.set 11
        block  ;; label = @3
          local.get 14
          local.get 25
          i32.wrap_i64
          local.get 28
          i64.const 1
          i64.add
          local.tee 28
          i32.wrap_i64
          i32.const 130000
          i32.mul
          local.tee 7
          local.get 25
          local.get 7
          i64.extend_i32_u
          i64.lt_u
          local.tee 22
          select
          local.tee 7
          i32.ge_s
          br_if 0 (;@3;)
          local.get 7
          local.get 9
          i32.add
          local.set 19
          local.get 10
          i64.extend_i32_u
          local.set 25
          i32.const 0
          local.set 7
          local.get 29
          local.set 14
          loop  ;; label = @4
            local.get 26
            i64.const 0
            i64.store
            local.get 27
            i64.const 0
            i64.store
            local.get 6
            i64.const 0
            i64.store offset=48
            block  ;; label = @5
              local.get 13
              br_if 0 (;@5;)
              i32.const 1187
              i32.const 2085
              i32.const 1174
              i32.const 1107
              call $__assert
            end
            local.get 6
            i32.const 48
            i32.add
            local.get 0
            local.get 1
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_
            local.get 6
            i32.const 24
            i32.add
            local.get 2
            i32.load
            call $std::__1::to_string_int_
            local.get 6
            i32.const 88
            i32.add
            i32.const 16
            i32.add
            local.get 6
            i32.const 48
            i32.add
            local.get 6
            i32.load offset=40
            local.get 24
            local.get 6
            i32.load8_u offset=24
            local.tee 15
            i32.const 1
            i32.and
            local.tee 16
            select
            local.get 6
            i64.load offset=32
            local.get 15
            i32.const 1
            i32.shr_u
            i64.extend_i32_u
            local.get 16
            select
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::append_char_const*__unsigned_long_
            local.tee 15
            i32.const 16
            i32.add
            local.tee 16
            i64.load
            i64.store
            local.get 6
            i32.const 88
            i32.add
            i32.const 8
            i32.add
            local.get 15
            i32.const 8
            i32.add
            local.tee 12
            i64.load
            i64.store
            local.get 6
            local.get 15
            i64.load
            i64.store offset=88
            local.get 15
            i64.const 0
            i64.store
            local.get 12
            i64.const 0
            i64.store
            local.get 16
            i64.const 0
            i64.store
            local.get 6
            local.get 4
            i32.load
            call $std::__1::to_string_int_
            local.get 6
            i32.const 10500144
            i32.add
            i32.const 16
            i32.add
            local.tee 16
            local.get 6
            i32.const 88
            i32.add
            local.get 6
            i32.load offset=16
            local.get 8
            local.get 6
            i32.load8_u
            local.tee 15
            i32.const 1
            i32.and
            local.tee 12
            select
            local.get 6
            i64.load offset=8
            local.get 15
            i32.const 1
            i32.shr_u
            i64.extend_i32_u
            local.get 12
            select
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::append_char_const*__unsigned_long_
            local.tee 15
            i32.const 16
            i32.add
            local.tee 12
            i64.load
            i64.store
            local.get 6
            i32.const 10500144
            i32.add
            i32.const 8
            i32.add
            local.tee 18
            local.get 15
            i32.const 8
            i32.add
            local.tee 31
            i64.load
            i64.store
            local.get 6
            local.get 15
            i64.load
            i64.store offset=10500144
            local.get 15
            i64.const 0
            i64.store
            local.get 31
            i64.const 0
            i64.store
            local.get 12
            i64.const 0
            i64.store
            local.get 6
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            local.get 6
            i32.const 88
            i32.add
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            local.get 6
            i32.const 24
            i32.add
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            local.get 6
            i32.const 48
            i32.add
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            i32.const 1312
            local.get 16
            i32.load
            local.get 20
            local.get 6
            i32.load8_u offset=10500144
            local.tee 15
            i32.const 1
            i32.and
            local.tee 16
            select
            local.get 18
            i64.load
            local.get 15
            i32.const 1
            i32.shr_u
            i64.extend_i32_u
            local.get 16
            select
            i64.const 1
            i64.add
            local.get 32
            local.get 7
            i32.const 72
            i32.mul
            i32.add
            call $prf_F_improve_void_const*__void_const*__unsigned_long__rand_t*_
            block  ;; label = @5
              local.get 6
              i64.load32_u offset=76
              local.get 6
              i32.load offset=72
              local.tee 15
              i64.extend_i32_u
              i64.sub
              i64.const 24
              i64.div_s
              local.tee 30
              local.get 25
              i64.gt_u
              br_if 0 (;@5;)
              i32.const 1134
              i32.const 1498
              i32.const 1227
              i32.const 1249
              call $__assert
              local.get 6
              i64.load32_u offset=76
              local.get 6
              i32.load offset=72
              local.tee 15
              i64.extend_i32_u
              i64.sub
              i64.const 24
              i64.div_s
              local.set 30
            end
            local.get 7
            i64.extend_i32_s
            local.set 34
            local.get 15
            local.get 14
            i32.add
            local.tee 16
            i32.const 16
            i32.add
            i32.load
            local.get 16
            i32.const 1
            i32.add
            local.get 16
            i32.load8_u
            local.tee 16
            i32.const 1
            i32.and
            local.tee 12
            select
            local.set 18
            block  ;; label = @5
              local.get 30
              local.get 25
              i64.gt_u
              br_if 0 (;@5;)
              i32.const 1134
              i32.const 1498
              i32.const 1227
              i32.const 1249
              call $__assert
              local.get 6
              i32.load offset=72
              local.tee 15
              local.get 14
              i32.add
              i32.load8_u
              local.tee 16
              i32.const 1
              i32.and
              local.set 12
            end
            i32.const 1328
            local.get 18
            local.get 15
            local.get 14
            i32.add
            i32.const 8
            i32.add
            i64.load
            local.get 16
            i32.const 1
            i32.shr_u
            i64.extend_i32_u
            local.get 12
            select
            local.get 33
            local.get 34
            i32.wrap_i64
            i32.const 72
            i32.mul
            i32.add
            call $prf_Enc_improve_void_const*__void_const*__unsigned_long__rand_t*_
            local.get 4
            local.get 4
            i32.load
            i32.const 1
            i32.add
            i32.store
            local.get 14
            i32.const 24
            i32.add
            local.set 14
            local.get 25
            i64.const 1
            i64.add
            local.set 25
            local.get 6
            i32.const 10500144
            i32.add
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            local.get 19
            local.get 7
            i32.const 1
            i32.add
            local.tee 7
            i32.ne
            br_if 0 (;@4;)
          end
        end
        local.get 32
        local.get 33
        local.get 11
        i64.const 32
        i64.shl
        i64.const 32
        i64.shr_s
        i64.const 130000
        local.get 22
        select
        i64.const 72
        i32.const 1264
        i64.const 4
        call $ocall_transfer_updated_entries
        drop
        local.get 29
        i32.const 3120000
        i32.add
        local.set 29
        local.get 9
        i32.const -130000
        i32.add
        local.set 9
        local.get 10
        i32.const 130000
        i32.add
        local.set 10
        br 0 (;@2;)
      end
    end
    local.get 6
    i32.const 10500224
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_update_doc (type 13) (param i32) (result i32)
    (local i32 i64 i32 i64 i32 i64 i32 i64 i32 i64 i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 80
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=72
      local.set 2
      local.get 0
      i32.load offset=64
      local.set 3
      local.get 0
      i64.load offset=56
      local.set 4
      local.get 0
      i32.load offset=48
      local.set 5
      local.get 0
      i64.load offset=40
      local.set 6
      local.get 0
      i32.load offset=32
      local.set 7
      local.get 0
      i64.load offset=24
      local.set 8
      local.get 0
      i32.load offset=16
      local.set 9
      local.get 0
      i64.load offset=8
      local.set 10
      block  ;; label = @2
        local.get 0
        i32.load
        local.tee 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 10
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 9
        i32.eqz
        br_if 0 (;@2;)
        local.get 9
        local.get 8
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 7
        i32.eqz
        br_if 0 (;@2;)
        local.get 7
        local.get 6
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 5
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        local.get 4
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        local.get 2
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 11
      i32.const 0
      local.set 12
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            local.set 12
            local.get 10
            i64.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 10
              call $malloc
              local.tee 12
              br_if 0 (;@5;)
              i32.const 3
              return
            end
            local.get 12
            local.get 10
            local.get 0
            local.get 10
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            local.set 7
            i32.const 1
            local.set 1
            i32.const 0
            local.set 9
            i32.const 0
            local.set 11
            i32.const 0
            local.set 0
            br 1 (;@3;)
          end
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                block  ;; label = @7
                  block  ;; label = @8
                    local.get 9
                    i32.eqz
                    br_if 0 (;@8;)
                    local.get 8
                    i64.eqz
                    br_if 0 (;@8;)
                    block  ;; label = @9
                      local.get 8
                      i64.const 3
                      i64.and
                      i64.const 0
                      i64.eq
                      br_if 0 (;@9;)
                      i32.const 2
                      local.set 1
                      br 3 (;@6;)
                    end
                    block  ;; label = @9
                      local.get 8
                      call $malloc
                      local.tee 11
                      br_if 0 (;@9;)
                      i32.const 3
                      local.set 1
                      br 3 (;@6;)
                    end
                    local.get 11
                    local.get 8
                    local.get 9
                    local.get 8
                    call $memcpy_s
                    i32.eqz
                    br_if 0 (;@8;)
                    i32.const 1
                    local.set 1
                    br 1 (;@7;)
                  end
                  i32.const 0
                  local.set 9
                  i32.const 0
                  local.set 0
                  block  ;; label = @8
                    local.get 7
                    i32.eqz
                    br_if 0 (;@8;)
                    i32.const 0
                    local.set 0
                    local.get 6
                    i64.eqz
                    br_if 0 (;@8;)
                    block  ;; label = @9
                      local.get 6
                      i64.const 3
                      i64.and
                      i64.const 0
                      i64.eq
                      br_if 0 (;@9;)
                      i32.const 2
                      local.set 1
                      br 2 (;@7;)
                    end
                    block  ;; label = @9
                      local.get 6
                      call $malloc
                      local.tee 0
                      br_if 0 (;@9;)
                      i32.const 3
                      local.set 1
                      br 2 (;@7;)
                    end
                    local.get 0
                    local.get 6
                    local.get 7
                    local.get 6
                    call $memcpy_s
                    i32.eqz
                    br_if 0 (;@8;)
                    i32.const 0
                    local.set 9
                    i32.const 1
                    local.set 1
                    i32.const 0
                    local.set 7
                    br 4 (;@4;)
                  end
                  block  ;; label = @8
                    local.get 5
                    i32.eqz
                    br_if 0 (;@8;)
                    local.get 4
                    i64.eqz
                    br_if 0 (;@8;)
                    i32.const 0
                    local.set 7
                    block  ;; label = @9
                      local.get 4
                      call $malloc
                      local.tee 9
                      br_if 0 (;@9;)
                      i32.const 3
                      local.set 1
                      i32.const 0
                      local.set 9
                      br 5 (;@4;)
                    end
                    i32.const 1
                    local.set 1
                    local.get 9
                    local.get 4
                    local.get 5
                    local.get 4
                    call $memcpy_s
                    br_if 4 (;@4;)
                  end
                  i32.const 0
                  local.set 1
                  i32.const 0
                  local.set 7
                  block  ;; label = @8
                    local.get 3
                    i32.eqz
                    br_if 0 (;@8;)
                    i32.const 0
                    local.set 7
                    local.get 2
                    i64.eqz
                    br_if 0 (;@8;)
                    i32.const 0
                    local.set 7
                    block  ;; label = @9
                      local.get 2
                      i64.const 3
                      i64.and
                      i64.const 0
                      i64.eq
                      br_if 0 (;@9;)
                      i32.const 2
                      local.set 1
                      br 5 (;@4;)
                    end
                    block  ;; label = @9
                      local.get 2
                      call $malloc
                      local.tee 7
                      br_if 0 (;@9;)
                      i32.const 3
                      local.set 1
                      i32.const 0
                      local.set 7
                      br 5 (;@4;)
                    end
                    local.get 7
                    local.get 2
                    local.get 3
                    local.get 2
                    call $memcpy_s
                    i32.eqz
                    br_if 0 (;@8;)
                    i32.const 1
                    local.set 1
                    br 4 (;@4;)
                  end
                  local.get 12
                  local.get 10
                  local.get 11
                  local.get 8
                  local.get 0
                  local.get 6
                  local.get 9
                  local.get 4
                  local.get 7
                  local.get 2
                  call $ecall_update_doc
                  br 3 (;@4;)
                end
                i32.const 0
                local.set 0
                br 1 (;@5;)
              end
              i32.const 0
              local.set 0
              i32.const 0
              local.set 11
            end
            i32.const 0
            local.set 9
            i32.const 0
            local.set 7
          end
          local.get 12
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 12
        call $free
      end
      block  ;; label = @2
        local.get 11
        i32.eqz
        br_if 0 (;@2;)
        local.get 11
        call $free
      end
      block  ;; label = @2
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        call $free
      end
      block  ;; label = @2
        local.get 9
        i32.eqz
        br_if 0 (;@2;)
        local.get 9
        call $free
      end
      local.get 7
      i32.eqz
      br_if 0 (;@1;)
      local.get 7
      call $free
    end
    local.get 1)
  (func $ecall_update_doc (type 19) (param i32 i64 i32 i64 i32 i64 i32 i64 i32 i64)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 224
    i32.sub
    local.tee 10
    global.set $__stack_pointer
    local.get 10
    i32.const 0
    i32.load
    i32.store offset=220
    local.get 10
    i32.const 72
    i32.add
    i32.const 16
    i32.add
    i64.const 0
    i64.store
    local.get 10
    i32.const 72
    i32.add
    i32.const 8
    i32.add
    i64.const 0
    i64.store
    local.get 10
    i64.const 0
    i64.store offset=72
    block  ;; label = @1
      local.get 1
      i64.eqz
      br_if 0 (;@1;)
      local.get 0
      br_if 0 (;@1;)
      i32.const 1187
      i32.const 2085
      i32.const 1174
      i32.const 1107
      call $__assert
    end
    local.get 10
    i32.const 72
    i32.add
    local.get 0
    local.get 1
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_
    local.get 10
    i32.const 24
    i32.add
    local.get 2
    i32.load
    call $std::__1::to_string_int_
    local.get 10
    i32.const 144
    i32.add
    i32.const 16
    i32.add
    local.get 10
    i32.const 72
    i32.add
    local.get 10
    i32.load offset=40
    local.get 10
    i32.const 24
    i32.add
    i32.const 1
    i32.or
    local.get 10
    i32.load8_u offset=24
    local.tee 0
    i32.const 1
    i32.and
    local.tee 2
    select
    local.get 10
    i64.load offset=32
    local.get 0
    i32.const 1
    i32.shr_u
    i64.extend_i32_u
    local.get 2
    select
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::append_char_const*__unsigned_long_
    local.tee 0
    i32.const 16
    i32.add
    local.tee 2
    i64.load
    i64.store
    local.get 10
    i32.const 144
    i32.add
    i32.const 8
    i32.add
    local.get 0
    i32.const 8
    i32.add
    local.tee 11
    i64.load
    i64.store
    local.get 10
    local.get 0
    i64.load
    i64.store offset=144
    local.get 0
    i64.const 0
    i64.store
    local.get 11
    i64.const 0
    i64.store
    local.get 2
    i64.const 0
    i64.store
    local.get 10
    local.get 4
    i32.load
    call $std::__1::to_string_int_
    local.get 10
    i32.const 48
    i32.add
    i32.const 16
    i32.add
    local.tee 2
    local.get 10
    i32.const 144
    i32.add
    local.get 10
    i32.load offset=16
    local.get 10
    i32.const 1
    i32.or
    local.get 10
    i32.load8_u
    local.tee 0
    i32.const 1
    i32.and
    local.tee 4
    select
    local.get 10
    i64.load offset=8
    local.get 0
    i32.const 1
    i32.shr_u
    i64.extend_i32_u
    local.get 4
    select
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::append_char_const*__unsigned_long_
    local.tee 0
    i32.const 16
    i32.add
    local.tee 4
    i64.load
    i64.store
    local.get 10
    i32.const 48
    i32.add
    i32.const 8
    i32.add
    local.tee 11
    local.get 0
    i32.const 8
    i32.add
    local.tee 12
    i64.load
    i64.store
    local.get 10
    local.get 0
    i64.load
    i64.store offset=48
    local.get 0
    i64.const 0
    i64.store
    local.get 12
    i64.const 0
    i64.store
    local.get 4
    i64.const 0
    i64.store
    local.get 10
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
    local.get 10
    i32.const 144
    i32.add
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
    local.get 10
    i32.const 24
    i32.add
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
    local.get 10
    i32.const 72
    i32.add
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
    i32.const 1312
    local.get 2
    i32.load
    local.get 10
    i32.const 48
    i32.add
    i32.const 1
    i32.or
    local.get 10
    i32.load8_u offset=48
    local.tee 0
    i32.const 1
    i32.and
    local.tee 2
    select
    local.get 11
    i64.load
    local.get 0
    i32.const 1
    i32.shr_u
    i64.extend_i32_u
    local.get 2
    select
    i64.const 1
    i64.add
    local.get 10
    i32.const 144
    i32.add
    call $prf_F_improve_void_const*__void_const*__unsigned_long__rand_t*_
    i32.const 1328
    local.get 6
    local.get 7
    local.get 10
    i32.const 72
    i32.add
    call $prf_Enc_improve_void_const*__void_const*__unsigned_long__rand_t*_
    local.get 10
    i32.const 144
    i32.add
    local.get 10
    i32.const 72
    i32.add
    i64.const 1
    i64.const 72
    local.get 8
    i64.const 4
    call $ocall_transfer_updated_entries
    drop
    local.get 10
    i32.const 48
    i32.add
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 10
      i32.load offset=220
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 10
    i32.const 224
    i32.add
    global.set $__stack_pointer)
  (func $ocall_print_int (type 13) (param i32) (result i32)
    (local i64 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        br_if 0 (;@2;)
        i64.const 0
        local.set 1
        br 1 (;@1;)
      end
      i64.const 8
      local.set 1
      local.get 0
      i64.const 8
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 1
    local.set 2
    block  ;; label = @1
      local.get 1
      i64.const 8
      i64.add
      call $sgx_ocalloc
      local.tee 3
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          local.get 3
          i64.extend_i32_u
          i64.const 8
          i64.add
          i32.wrap_i64
          local.tee 4
          i32.store
          local.get 4
          local.get 1
          local.get 0
          i64.const 8
          call $memcpy_s
          i32.eqz
          br_if 1 (;@2;)
          br 2 (;@1;)
        end
        local.get 3
        i32.const 0
        i32.store
      end
      i32.const 0
      local.get 3
      call $sgx_ocall
      local.set 2
    end
    call $sgx_ocfree
    local.get 2)
  (func $ocall_print_string (type 13) (param i32) (result i32)
    (local i64 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          br_if 0 (;@3;)
          i64.const 0
          local.set 1
          br 1 (;@2;)
        end
        i32.const 2
        local.set 2
        local.get 0
        local.get 0
        call $strlen
        i64.const 1
        i64.add
        local.tee 1
        call $sgx_is_within_enclave
        i32.eqz
        br_if 1 (;@1;)
        local.get 1
        i64.const -9
        i64.gt_u
        br_if 1 (;@1;)
      end
      i32.const 1
      local.set 2
      block  ;; label = @2
        local.get 1
        i64.const 8
        i64.add
        call $sgx_ocalloc
        local.tee 3
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 3
            local.get 3
            i32.const 8
            i32.add
            local.tee 4
            i32.store
            local.get 4
            local.get 1
            local.get 0
            local.get 1
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 3
          i32.const 0
          i32.store
        end
        i32.const 1
        local.get 3
        call $sgx_ocall
        local.set 2
      end
      call $sgx_ocfree
    end
    local.get 2)
  (func $ocall_get_docId (type 20) (param i32 i32 i64 i64 i32 i64) (result i32)
    (local i64 i32 i64 i64 i32 i32)
    local.get 3
    local.get 2
    i64.mul
    local.set 6
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 6
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    block  ;; label = @1
      local.get 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      local.get 6
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    block  ;; label = @1
      local.get 4
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      local.get 5
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 2
    local.set 7
    block  ;; label = @1
      local.get 6
      i64.const 0
      local.get 0
      select
      local.tee 8
      i64.const -49
      i64.gt_u
      br_if 0 (;@1;)
      local.get 8
      i64.const 48
      i64.add
      local.tee 8
      local.get 6
      i64.const 0
      local.get 1
      select
      i64.add
      local.tee 9
      local.get 8
      i64.lt_u
      br_if 0 (;@1;)
      local.get 9
      local.get 5
      i64.const 0
      local.get 4
      select
      i64.add
      local.tee 8
      local.get 9
      i64.lt_u
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 8
          call $sgx_ocalloc
          local.tee 10
          br_if 0 (;@3;)
          i32.const 1
          local.set 7
          br 1 (;@2;)
        end
        local.get 10
        i64.extend_i32_u
        i64.const 48
        i64.add
        local.tee 9
        i32.wrap_i64
        local.set 11
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 10
            local.get 11
            i32.store
            block  ;; label = @5
              local.get 11
              local.get 8
              i64.const -48
              i64.add
              local.get 0
              local.get 6
              call $memcpy_s
              i32.eqz
              br_if 0 (;@5;)
              i32.const 1
              local.set 7
              br 3 (;@2;)
            end
            local.get 9
            local.get 6
            i64.add
            i32.wrap_i64
            local.set 11
            br 1 (;@3;)
          end
          local.get 10
          i32.const 0
          i32.store
        end
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.eqz
            br_if 0 (;@4;)
            local.get 10
            local.get 11
            i32.store offset=8
            local.get 6
            local.get 11
            i32.const 0
            local.get 6
            i32.wrap_i64
            call $memset
            i64.extend_i32_u
            i64.add
            i32.wrap_i64
            local.set 0
            br 1 (;@3;)
          end
          local.get 10
          i32.const 0
          i32.store offset=8
          local.get 11
          local.set 0
          i32.const 0
          local.set 11
        end
        local.get 10
        local.get 3
        i64.store offset=24
        local.get 10
        local.get 2
        i64.store offset=16
        block  ;; label = @3
          block  ;; label = @4
            local.get 4
            i32.eqz
            br_if 0 (;@4;)
            local.get 10
            local.get 0
            i32.store offset=32
            i32.const 2
            local.set 7
            local.get 5
            i64.const 7
            i64.and
            i64.const 0
            i64.ne
            br_if 2 (;@2;)
            local.get 0
            i32.const 0
            local.get 5
            i32.wrap_i64
            call $memset
            drop
            br 1 (;@3;)
          end
          i32.const 0
          local.set 0
          local.get 10
          i32.const 0
          i32.store offset=32
        end
        local.get 10
        local.get 5
        i64.store offset=40
        block  ;; label = @3
          i32.const 2
          local.get 10
          call $sgx_ocall
          local.tee 10
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            local.get 6
            local.get 11
            local.get 6
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 7
            br 2 (;@2;)
          end
          local.get 4
          i32.eqz
          br_if 0 (;@3;)
          i32.const 1
          local.set 7
          local.get 4
          local.get 5
          local.get 0
          local.get 5
          call $memcpy_s
          br_if 1 (;@2;)
        end
        local.get 10
        local.set 7
      end
      call $sgx_ocfree
    end
    local.get 7)
  (func $ocall_get_delId (type 20) (param i32 i32 i64 i64 i32 i64) (result i32)
    (local i64 i32 i64 i64 i32 i32)
    local.get 3
    local.get 2
    i64.mul
    local.set 6
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 6
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    block  ;; label = @1
      local.get 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      local.get 6
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    block  ;; label = @1
      local.get 4
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      local.get 5
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 2
    local.set 7
    block  ;; label = @1
      local.get 6
      i64.const 0
      local.get 0
      select
      local.tee 8
      i64.const -49
      i64.gt_u
      br_if 0 (;@1;)
      local.get 8
      i64.const 48
      i64.add
      local.tee 8
      local.get 6
      i64.const 0
      local.get 1
      select
      i64.add
      local.tee 9
      local.get 8
      i64.lt_u
      br_if 0 (;@1;)
      local.get 9
      local.get 5
      i64.const 0
      local.get 4
      select
      i64.add
      local.tee 8
      local.get 9
      i64.lt_u
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 8
          call $sgx_ocalloc
          local.tee 10
          br_if 0 (;@3;)
          i32.const 1
          local.set 7
          br 1 (;@2;)
        end
        local.get 10
        i64.extend_i32_u
        i64.const 48
        i64.add
        local.tee 9
        i32.wrap_i64
        local.set 11
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 10
            local.get 11
            i32.store
            block  ;; label = @5
              local.get 11
              local.get 8
              i64.const -48
              i64.add
              local.get 0
              local.get 6
              call $memcpy_s
              i32.eqz
              br_if 0 (;@5;)
              i32.const 1
              local.set 7
              br 3 (;@2;)
            end
            local.get 9
            local.get 6
            i64.add
            i32.wrap_i64
            local.set 11
            br 1 (;@3;)
          end
          local.get 10
          i32.const 0
          i32.store
        end
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.eqz
            br_if 0 (;@4;)
            local.get 10
            local.get 11
            i32.store offset=8
            local.get 6
            local.get 11
            i32.const 0
            local.get 6
            i32.wrap_i64
            call $memset
            i64.extend_i32_u
            i64.add
            i32.wrap_i64
            local.set 0
            br 1 (;@3;)
          end
          local.get 10
          i32.const 0
          i32.store offset=8
          local.get 11
          local.set 0
          i32.const 0
          local.set 11
        end
        local.get 10
        local.get 3
        i64.store offset=24
        local.get 10
        local.get 2
        i64.store offset=16
        block  ;; label = @3
          block  ;; label = @4
            local.get 4
            i32.eqz
            br_if 0 (;@4;)
            local.get 10
            local.get 0
            i32.store offset=32
            i32.const 2
            local.set 7
            local.get 5
            i64.const 7
            i64.and
            i64.const 0
            i64.ne
            br_if 2 (;@2;)
            local.get 0
            i32.const 0
            local.get 5
            i32.wrap_i64
            call $memset
            drop
            br 1 (;@3;)
          end
          i32.const 0
          local.set 0
          local.get 10
          i32.const 0
          i32.store offset=32
        end
        local.get 10
        local.get 5
        i64.store offset=40
        block  ;; label = @3
          i32.const 3
          local.get 10
          call $sgx_ocall
          local.tee 10
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            local.get 6
            local.get 11
            local.get 6
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 7
            br 2 (;@2;)
          end
          local.get 4
          i32.eqz
          br_if 0 (;@3;)
          i32.const 1
          local.set 7
          local.get 4
          local.get 5
          local.get 0
          local.get 5
          call $memcpy_s
          br_if 1 (;@2;)
        end
        local.get 10
        local.set 7
      end
      call $sgx_ocfree
    end
    local.get 7)
  (func $ocall_send_to_client (type 21) (param i32 i64 i64) (result i32)
    (local i64 i64 i32 i32 i32)
    local.get 2
    local.get 1
    i64.mul
    local.set 3
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          br_if 0 (;@3;)
          i64.const 0
          local.set 4
          br 1 (;@2;)
        end
        i32.const 2
        local.set 5
        local.get 0
        local.get 3
        call $sgx_is_within_enclave
        i32.eqz
        br_if 1 (;@1;)
        local.get 3
        local.set 4
        local.get 3
        i64.const -25
        i64.gt_u
        br_if 1 (;@1;)
      end
      i32.const 1
      local.set 5
      block  ;; label = @2
        local.get 4
        i64.const 24
        i64.add
        call $sgx_ocalloc
        local.tee 6
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 6
            local.get 6
            i32.const 24
            i32.add
            local.tee 7
            i32.store
            local.get 7
            local.get 4
            local.get 0
            local.get 3
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 6
          i32.const 0
          i32.store
        end
        local.get 6
        local.get 2
        i64.store offset=16
        local.get 6
        local.get 1
        i64.store offset=8
        i32.const 4
        local.get 6
        call $sgx_ocall
        local.set 5
      end
      call $sgx_ocfree
    end
    local.get 5)
  (func $ocall_transfer_updated_entries (type 20) (param i32 i32 i64 i64 i32 i64) (result i32)
    (local i64 i32 i64 i64 i32 i32)
    local.get 3
    local.get 2
    i64.mul
    local.set 6
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 6
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    block  ;; label = @1
      local.get 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      local.get 6
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    block  ;; label = @1
      local.get 4
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      local.get 5
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 2
    local.set 7
    block  ;; label = @1
      local.get 6
      i64.const 0
      local.get 0
      select
      local.tee 8
      i64.const -49
      i64.gt_u
      br_if 0 (;@1;)
      local.get 8
      i64.const 48
      i64.add
      local.tee 8
      local.get 6
      i64.const 0
      local.get 1
      select
      i64.add
      local.tee 9
      local.get 8
      i64.lt_u
      br_if 0 (;@1;)
      local.get 9
      local.get 5
      i64.const 0
      local.get 4
      select
      i64.add
      local.tee 8
      local.get 9
      i64.lt_u
      br_if 0 (;@1;)
      i32.const 1
      local.set 7
      block  ;; label = @2
        local.get 8
        call $sgx_ocalloc
        local.tee 10
        i32.eqz
        br_if 0 (;@2;)
        local.get 8
        i64.const -48
        i64.add
        local.set 8
        local.get 10
        i64.extend_i32_u
        i64.const 48
        i64.add
        local.tee 9
        i32.wrap_i64
        local.set 11
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 10
            local.get 11
            i32.store
            local.get 11
            local.get 8
            local.get 0
            local.get 6
            call $memcpy_s
            br_if 2 (;@2;)
            local.get 8
            local.get 6
            i64.sub
            local.set 8
            local.get 9
            local.get 6
            i64.add
            i32.wrap_i64
            local.set 11
            br 1 (;@3;)
          end
          local.get 10
          i32.const 0
          i32.store
        end
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.eqz
            br_if 0 (;@4;)
            local.get 10
            local.get 11
            i32.store offset=8
            local.get 11
            local.get 8
            local.get 1
            local.get 6
            call $memcpy_s
            br_if 2 (;@2;)
            local.get 8
            local.get 6
            i64.sub
            local.set 8
            local.get 6
            local.get 11
            i64.extend_i32_u
            i64.add
            i32.wrap_i64
            local.set 11
            br 1 (;@3;)
          end
          local.get 10
          i32.const 0
          i32.store offset=8
        end
        local.get 10
        local.get 3
        i64.store offset=24
        local.get 10
        local.get 2
        i64.store offset=16
        block  ;; label = @3
          block  ;; label = @4
            local.get 4
            i32.eqz
            br_if 0 (;@4;)
            local.get 10
            local.get 11
            i32.store offset=32
            i32.const 2
            local.set 7
            local.get 5
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            br_if 2 (;@2;)
            i32.const 1
            local.set 7
            local.get 11
            local.get 8
            local.get 4
            local.get 5
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 10
          i32.const 0
          i32.store offset=32
        end
        local.get 10
        local.get 5
        i64.store offset=40
        i32.const 5
        local.get 10
        call $sgx_ocall
        local.set 7
      end
      call $sgx_ocfree
    end
    local.get 7)
  (func $sgx_oc_cpuidex (type 7) (param i32 i32 i32) (result i32)
    (local i64 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        br_if 0 (;@2;)
        i64.const 16
        local.set 3
        br 1 (;@1;)
      end
      i64.const 32
      local.set 3
      local.get 0
      i64.const 16
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 1
    local.set 4
    block  ;; label = @1
      local.get 3
      call $sgx_ocalloc
      local.tee 5
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          local.get 5
          i64.extend_i32_u
          i64.const 16
          i64.add
          local.tee 3
          i64.store32
          local.get 3
          i32.wrap_i64
          local.tee 6
          i32.const 8
          i32.add
          i64.const 0
          i64.store align=1
          local.get 6
          i64.const 0
          i64.store align=1
          br 1 (;@2;)
        end
        i32.const 0
        local.set 6
        local.get 5
        i32.const 0
        i32.store
      end
      local.get 5
      local.get 2
      i32.store offset=12
      local.get 5
      local.get 1
      i32.store offset=8
      block  ;; label = @2
        i32.const 6
        local.get 5
        call $sgx_ocall
        local.tee 5
        br_if 0 (;@2;)
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i64.const 16
        local.get 6
        i64.const 16
        call $memcpy_s
        br_if 1 (;@1;)
      end
      local.get 5
      local.set 4
    end
    call $sgx_ocfree
    local.get 4)
  (func $sgx_thread_wait_untrusted_event_ocall (type 4) (param i32 i32) (result i32)
    (local i32)
    block  ;; label = @1
      i64.const 16
      call $sgx_ocalloc
      local.tee 2
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    local.get 2
    local.get 1
    i32.store offset=8
    block  ;; label = @1
      i32.const 7
      local.get 2
      call $sgx_ocall
      local.tee 1
      br_if 0 (;@1;)
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 2
      i32.load
      i32.store
    end
    call $sgx_ocfree
    local.get 1)
  (func $sgx_thread_set_untrusted_event_ocall (type 4) (param i32 i32) (result i32)
    (local i32)
    block  ;; label = @1
      i64.const 16
      call $sgx_ocalloc
      local.tee 2
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    local.get 2
    local.get 1
    i32.store offset=8
    block  ;; label = @1
      i32.const 8
      local.get 2
      call $sgx_ocall
      local.tee 1
      br_if 0 (;@1;)
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 2
      i32.load
      i32.store
    end
    call $sgx_ocfree
    local.get 1)
  (func $sgx_thread_setwait_untrusted_events_ocall (type 7) (param i32 i32 i32) (result i32)
    (local i32)
    block  ;; label = @1
      i64.const 24
      call $sgx_ocalloc
      local.tee 3
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    local.get 3
    local.get 2
    i32.store offset=16
    local.get 3
    local.get 1
    i32.store offset=8
    block  ;; label = @1
      i32.const 9
      local.get 3
      call $sgx_ocall
      local.tee 1
      br_if 0 (;@1;)
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 3
      i32.load
      i32.store
    end
    call $sgx_ocfree
    local.get 1)
  (func $sgx_thread_set_multiple_untrusted_events_ocall (type 11) (param i32 i32 i64) (result i32)
    (local i64 i64 i32 i32 i32)
    local.get 2
    i64.const 3
    i64.shl
    local.set 3
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          br_if 0 (;@3;)
          i64.const 0
          local.set 4
          br 1 (;@2;)
        end
        i32.const 2
        local.set 5
        local.get 1
        local.get 3
        call $sgx_is_within_enclave
        i32.eqz
        br_if 1 (;@1;)
        local.get 3
        local.set 4
        local.get 3
        i64.const -25
        i64.gt_u
        br_if 1 (;@1;)
      end
      i32.const 1
      local.set 5
      block  ;; label = @2
        local.get 4
        i64.const 24
        i64.add
        call $sgx_ocalloc
        local.tee 6
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.eqz
            br_if 0 (;@4;)
            local.get 6
            local.get 6
            i64.extend_i32_u
            i64.const 24
            i64.add
            i32.wrap_i64
            local.tee 7
            i32.store offset=8
            local.get 7
            local.get 4
            local.get 1
            local.get 3
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 6
          i32.const 0
          i32.store offset=8
        end
        local.get 6
        local.get 2
        i64.store offset=16
        i32.const 10
        local.get 6
        call $sgx_ocall
        local.tee 5
        br_if 0 (;@2;)
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 6
        i32.load
        i32.store
      end
      call $sgx_ocfree
    end
    local.get 5)
  (func $_GLOBAL__sub_I_CryptoEnclave.cpp (type 5)
    i32.const 0
    i64.const 0
    i64.store offset=1296
    i32.const 0
    i64.const 0
    i64.store offset=1288
    i32.const 0
    i64.const 0
    i64.store offset=1280
    i32.const 1280
    i32.const 1238
    i64.const 10
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_
    i32.const 1
    i32.const 1280
    i32.const 1024
    call $__cxa_atexit
    drop)
  (func $prf_F_improve_void_const*__void_const*__unsigned_long__rand_t*_ (type 22) (param i32 i32 i64 i32)
    local.get 3
    local.get 2
    i64.const 28
    i64.add
    i64.store
    local.get 0
    local.get 1
    local.get 2
    i32.wrap_i64
    local.get 3
    i32.const 36
    i32.add
    i32.const 1268
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 3
    i32.const 8
    i32.add
    call $sgx_rijndael128GCM_encrypt
    drop
    local.get 3
    i32.const 32
    i32.add
    i32.const 0
    i32.load offset=1276 align=1
    i32.store align=1
    local.get 3
    i32.const 24
    i32.add
    i32.const 0
    i64.load offset=1268 align=1
    i64.store align=1)
  (func $prf_Dec_improve_void_const*__void_const*__unsigned_long__rand_t*_ (type 22) (param i32 i32 i64 i32)
    local.get 3
    local.get 2
    i64.const -28
    i64.add
    local.tee 2
    i64.store
    local.get 0
    local.get 1
    i32.const 28
    i32.add
    local.get 2
    i32.wrap_i64
    local.get 3
    i32.const 8
    i32.add
    i32.const 1268
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 1
    call $sgx_rijndael128GCM_decrypt
    drop)
  (func $std::__1::back_insert_iterator<std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>_>_std::__1::__set_difference<std::__1::__less<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>&__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::back_insert_iterator<std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>_>_>_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::back_insert_iterator<std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>_>__std::__1::__less<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>&_ (type 23) (param i32 i32 i32 i32 i32 i32) (result i32)
    (local i32 i32 i64 i64 i32 i64 i32)
    block  ;; label = @1
      local.get 0
      local.get 1
      i32.eq
      br_if 0 (;@1;)
      loop  ;; label = @2
        block  ;; label = @3
          local.get 2
          local.get 3
          i32.ne
          br_if 0 (;@3;)
          loop  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                local.get 4
                i32.load offset=4
                local.tee 2
                local.get 4
                i32.load offset=8
                i32.eq
                br_if 0 (;@6;)
                local.get 2
                local.get 0
                call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::basic_string_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&_
                local.get 4
                local.get 4
                i32.load offset=4
                i32.const 24
                i32.add
                i32.store offset=4
                br 1 (;@5;)
              end
              local.get 4
              local.get 0
              call $void_std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>::__push_back_slow_path<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&>_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&_
            end
            local.get 0
            i32.const 24
            i32.add
            local.tee 0
            local.get 1
            i32.ne
            br_if 0 (;@4;)
            br 3 (;@1;)
          end
        end
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                block  ;; label = @7
                  block  ;; label = @8
                    local.get 2
                    i64.load offset=8
                    local.get 2
                    i32.load8_u
                    local.tee 6
                    i32.const 1
                    i32.shr_u
                    i64.extend_i32_u
                    local.get 6
                    i32.const 1
                    i32.and
                    local.tee 7
                    select
                    local.tee 8
                    local.get 0
                    i64.load offset=8
                    local.get 0
                    i32.load8_u
                    local.tee 6
                    i32.const 1
                    i32.shr_u
                    i64.extend_i32_u
                    local.get 6
                    i32.const 1
                    i32.and
                    local.tee 6
                    select
                    local.tee 9
                    local.get 8
                    local.get 9
                    i64.lt_u
                    local.tee 10
                    select
                    local.tee 11
                    i64.eqz
                    br_if 0 (;@8;)
                    block  ;; label = @9
                      local.get 0
                      i32.load offset=16
                      local.get 0
                      i32.const 1
                      i32.add
                      local.get 6
                      select
                      local.tee 12
                      local.get 2
                      i32.load offset=16
                      local.get 2
                      i32.const 1
                      i32.add
                      local.get 7
                      select
                      local.tee 7
                      local.get 11
                      call $memcmp
                      local.tee 6
                      br_if 0 (;@9;)
                      local.get 9
                      local.get 8
                      i64.lt_u
                      br_if 2 (;@7;)
                      br 3 (;@6;)
                    end
                    local.get 6
                    i32.const -1
                    i32.gt_s
                    br_if 2 (;@6;)
                    br 1 (;@7;)
                  end
                  local.get 9
                  local.get 8
                  i64.ge_u
                  br_if 2 (;@5;)
                end
                block  ;; label = @7
                  block  ;; label = @8
                    local.get 4
                    i32.load offset=4
                    local.tee 6
                    local.get 4
                    i32.load offset=8
                    i32.eq
                    br_if 0 (;@8;)
                    local.get 6
                    local.get 0
                    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::basic_string_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&_
                    local.get 4
                    local.get 4
                    i32.load offset=4
                    i32.const 24
                    i32.add
                    i32.store offset=4
                    br 1 (;@7;)
                  end
                  local.get 4
                  local.get 0
                  call $void_std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>::__push_back_slow_path<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&>_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&_
                end
                local.get 0
                i32.const 24
                i32.add
                local.set 0
                br 3 (;@3;)
              end
              local.get 7
              local.get 12
              local.get 11
              call $memcmp
              local.tee 6
              br_if 1 (;@4;)
            end
            i32.const -1
            i32.const 0
            local.get 10
            select
            local.set 6
          end
          local.get 2
          i32.const 24
          i32.add
          local.set 2
          local.get 0
          local.get 6
          i32.const -1
          i32.xor
          i32.const 31
          i32.shr_u
          i32.const 24
          i32.mul
          i32.add
          local.set 0
        end
        local.get 0
        local.get 1
        i32.ne
        br_if 0 (;@2;)
      end
    end
    local.get 4)
  (func $prf_Enc_improve_void_const*__void_const*__unsigned_long__rand_t*_ (type 22) (param i32 i32 i64 i32)
    local.get 3
    local.get 2
    i64.const 28
    i64.add
    i64.store
    local.get 0
    local.get 1
    local.get 2
    i32.wrap_i64
    local.get 3
    i32.const 36
    i32.add
    i32.const 1268
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 3
    i32.const 8
    i32.add
    call $sgx_rijndael128GCM_encrypt
    drop
    local.get 3
    i32.const 32
    i32.add
    i32.const 0
    i32.load offset=1276 align=1
    i32.store align=1
    local.get 3
    i32.const 24
    i32.add
    i32.const 0
    i64.load offset=1268 align=1
    i64.store align=1)
  (func $__clang_call_terminate (type 3) (param i32)
    local.get 0
    call $__cxa_begin_catch
    drop
    call $std::terminate__
    unreachable)
  (func $void_std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>::__push_back_slow_path<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&>_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&_ (type 10) (param i32 i32)
    (local i32 i32 i64 i64 i64 i64 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 0
    i32.const 8
    i32.add
    local.set 3
    block  ;; label = @1
      local.get 0
      i64.load32_u offset=4
      local.get 0
      i64.load32_u
      local.tee 4
      i64.sub
      i64.const 24
      i64.div_s
      local.tee 5
      i64.const 1
      i64.add
      local.tee 6
      i64.const 768614336404564651
      i64.lt_u
      br_if 0 (;@1;)
      local.get 0
      call $std::__1::__vector_base_common<true>::__throw_length_error___const
      local.get 0
      i64.load32_u offset=4
      local.get 0
      i64.load32_u
      local.tee 4
      i64.sub
      i64.const 24
      i64.div_s
      local.set 5
    end
    local.get 2
    i32.const 24
    i32.add
    local.get 3
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 6
          local.get 0
          i64.load32_u offset=8
          local.get 4
          i64.sub
          i64.const 24
          i64.div_s
          local.tee 4
          i64.const 1
          i64.shl
          local.tee 7
          local.get 7
          local.get 6
          i64.lt_u
          select
          i64.const 768614336404564650
          local.get 4
          i64.const 384307168202282325
          i64.lt_u
          select
          local.tee 6
          i64.eqz
          i32.eqz
          br_if 0 (;@3;)
          i32.const 0
          local.set 3
          br 1 (;@2;)
        end
        local.get 6
        i64.const 768614336404564651
        i64.ge_u
        br_if 1 (;@1;)
        local.get 6
        i64.const 24
        i64.mul
        call $operator_new_unsigned_long_
        local.set 3
      end
      local.get 2
      local.get 3
      i32.store offset=8
      local.get 2
      local.get 3
      local.get 5
      i32.wrap_i64
      i32.const 24
      i32.mul
      i32.add
      local.tee 8
      i32.store offset=16
      local.get 2
      local.get 3
      local.get 6
      i32.wrap_i64
      i32.const 24
      i32.mul
      i32.add
      local.tee 9
      i32.store offset=20
      local.get 2
      local.get 8
      i32.store offset=12
      local.get 8
      local.get 1
      call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::basic_string_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&_
      local.get 8
      i32.const 24
      i32.add
      local.set 10
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=4
          local.tee 3
          local.get 0
          i32.load
          local.tee 1
          i32.ne
          br_if 0 (;@3;)
          local.get 1
          local.set 3
          br 1 (;@2;)
        end
        loop  ;; label = @3
          local.get 8
          i32.const -24
          i32.add
          local.tee 8
          local.get 3
          i32.const -24
          i32.add
          local.tee 3
          i64.load
          i64.store
          local.get 8
          i32.const 16
          i32.add
          local.get 3
          i32.const 16
          i32.add
          local.tee 11
          i64.load
          i64.store
          local.get 8
          i32.const 8
          i32.add
          local.get 3
          i32.const 8
          i32.add
          local.tee 12
          i64.load
          i64.store
          local.get 3
          i64.const 0
          i64.store
          local.get 12
          i64.const 0
          i64.store
          local.get 11
          i64.const 0
          i64.store
          local.get 3
          local.get 1
          i32.ne
          br_if 0 (;@3;)
        end
        local.get 0
        i32.load offset=4
        local.set 1
        local.get 0
        i32.load
        local.set 3
      end
      local.get 0
      local.get 9
      i32.store offset=8
      local.get 0
      local.get 10
      i32.store offset=4
      local.get 0
      local.get 8
      i32.store
      block  ;; label = @2
        local.get 1
        local.get 3
        i32.eq
        br_if 0 (;@2;)
        loop  ;; label = @3
          local.get 1
          i32.const -24
          i32.add
          local.tee 1
          call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
          local.get 1
          local.get 3
          i32.ne
          br_if 0 (;@3;)
        end
      end
      block  ;; label = @2
        local.get 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        call $operator_delete_void*_
      end
      local.get 2
      i32.const 32
      i32.add
      global.set $__stack_pointer
      return
    end
    i64.const 8
    call $__cxa_allocate_exception
    local.tee 3
    call $std::bad_alloc::bad_alloc__
    local.get 3
    i32.const 0
    i32.const 2
    call $__cxa_throw
    unreachable)
  (func $std::__1::__vector_base<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>::~__vector_base__ (type 3) (param i32)
    (local i32 i32)
    block  ;; label = @1
      local.get 0
      i32.load
      local.tee 1
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 0
        i32.load offset=4
        local.tee 2
        local.get 1
        i32.eq
        br_if 0 (;@2;)
        loop  ;; label = @3
          local.get 0
          local.get 2
          i32.const -24
          i32.add
          local.tee 2
          i32.store offset=4
          local.get 2
          call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
          local.get 0
          i32.load offset=4
          local.tee 2
          local.get 1
          i32.ne
          br_if 0 (;@3;)
        end
        local.get 0
        i32.load
        local.set 1
      end
      local.get 1
      call $operator_delete_void*_
    end)
  (func $std::__1::__split_buffer<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>&>::~__split_buffer__ (type 3) (param i32)
    (local i32 i32)
    block  ;; label = @1
      local.get 0
      i32.load offset=8
      local.tee 1
      local.get 0
      i32.load offset=4
      local.tee 2
      i32.eq
      br_if 0 (;@1;)
      loop  ;; label = @2
        local.get 0
        local.get 1
        i32.const -24
        i32.add
        local.tee 1
        i32.store offset=8
        local.get 1
        call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
        local.get 0
        i32.load offset=8
        local.tee 1
        local.get 2
        i32.ne
        br_if 0 (;@2;)
      end
    end
    block  ;; label = @1
      local.get 0
      i32.load
      local.tee 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      call $operator_delete_void*_
    end)
  (func $_GLOBAL__sub_I_EnclaveUtils.cpp (type 5)
    i32.const 0
    i64.const 0
    i64.store offset=1360
    i32.const 0
    i64.const 0
    i64.store offset=1352
    i32.const 0
    i64.const 0
    i64.store offset=1344
    i32.const 1344
    i32.const 1238
    i64.const 10
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_
    i32.const 1
    i32.const 1344
    i32.const 1024
    call $__cxa_atexit
    drop)
  (func $printf_char_const*__..._ (type 10) (param i32 i32)
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
  (func $print_bytes_unsigned_char*__unsigned_int_ (type 10) (param i32 i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    block  ;; label = @1
      local.get 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      i64.extend_i32_u
      local.set 3
      loop  ;; label = @2
        local.get 2
        local.get 0
        i32.load8_u
        i32.store
        i32.const 1104
        local.get 2
        call $printf_char_const*__..._
        local.get 0
        i32.const 1
        i32.add
        local.set 0
        local.get 3
        i64.const -1
        i64.add
        local.tee 3
        i64.eqz
        i32.eqz
        br_if 0 (;@2;)
      end
    end
    i32.const 1262
    i32.const 0
    call $printf_char_const*__..._
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $cmp_unsigned_char_const*__unsigned_char_const*__unsigned_int_ (type 7) (param i32 i32 i32) (result i32)
    (local i32 i64 i64 i64)
    block  ;; label = @1
      local.get 2
      br_if 0 (;@1;)
      i32.const 0
      return
    end
    i32.const -1
    local.set 3
    block  ;; label = @1
      local.get 0
      i32.load8_u
      local.get 1
      i32.load8_u
      i32.ne
      br_if 0 (;@1;)
      local.get 2
      i64.extend_i32_u
      local.set 4
      local.get 0
      i32.const 1
      i32.add
      local.set 2
      local.get 1
      i32.const 1
      i32.add
      local.set 0
      i64.const 1
      local.set 5
      block  ;; label = @2
        loop  ;; label = @3
          local.get 4
          local.get 5
          local.tee 6
          i64.eq
          br_if 1 (;@2;)
          local.get 6
          i64.const 1
          i64.add
          local.set 5
          local.get 0
          i32.load8_u
          local.set 1
          local.get 2
          i32.load8_u
          local.set 3
          local.get 2
          i32.const 1
          i32.add
          local.set 2
          local.get 0
          i32.const 1
          i32.add
          local.set 0
          local.get 3
          local.get 1
          i32.eq
          br_if 0 (;@3;)
        end
      end
      i32.const -1
      i32.const 0
      local.get 6
      local.get 4
      i64.lt_u
      select
      local.set 3
    end
    local.get 3)
  (func $clear_unsigned_char*__unsigned_int_ (type 10) (param i32 i32)
    block  ;; label = @1
      local.get 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.const 0
      local.get 1
      call $memset
      drop
    end)
  (func $wordTokenize_char*__int_ (type 14) (param i32 i32 i32)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 0
    i64.const 0
    i64.store
    local.get 0
    i32.const 8
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i32.const 16
    i32.add
    i64.const 0
    i64.store
    local.get 3
    i32.const 44
    i32.store16 offset=30
    block  ;; label = @1
      local.get 1
      local.get 3
      i32.const 30
      i32.add
      call $strtok
      local.tee 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 3
      i32.const 16
      i32.add
      local.set 4
      local.get 3
      i32.const 8
      i32.add
      local.set 5
      loop  ;; label = @2
        local.get 4
        i64.const 0
        i64.store
        local.get 5
        i64.const 0
        i64.store
        local.get 3
        i64.const 0
        i64.store
        local.get 3
        local.get 1
        local.get 1
        call $strlen
        call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.load offset=4
            local.tee 1
            local.get 0
            i32.load offset=8
            i32.ge_u
            br_if 0 (;@4;)
            local.get 1
            local.get 3
            i64.load
            i64.store
            local.get 1
            i32.const 16
            i32.add
            local.get 4
            i64.load
            i64.store
            local.get 1
            i32.const 8
            i32.add
            local.get 5
            i64.load
            i64.store
            local.get 5
            i64.const 0
            i64.store
            local.get 4
            i64.const 0
            i64.store
            local.get 0
            local.get 0
            i32.load offset=4
            i32.const 24
            i32.add
            i32.store offset=4
            local.get 3
            i64.const 0
            i64.store
            br 1 (;@3;)
          end
          local.get 0
          local.get 3
          call $void_std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>::__push_back_slow_path<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>&&_
        end
        local.get 3
        call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
        i32.const 0
        local.get 3
        i32.const 30
        i32.add
        call $strtok
        local.tee 1
        br_if 0 (;@2;)
      end
    end
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $void_std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>::__push_back_slow_path<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>&&_ (type 10) (param i32 i32)
    (local i64 i64 i64 i64 i32 i32 i64 i32 i32 i32 i32)
    block  ;; label = @1
      local.get 0
      i64.load32_u offset=4
      local.get 0
      i64.load32_u
      local.tee 2
      i64.sub
      i64.const 24
      i64.div_s
      local.tee 3
      i64.const 1
      i64.add
      local.tee 4
      i64.const 768614336404564651
      i64.lt_u
      br_if 0 (;@1;)
      local.get 0
      call $std::__1::__vector_base_common<true>::__throw_length_error___const
      local.get 0
      i64.load32_u offset=4
      local.get 0
      i64.load32_u
      local.tee 2
      i64.sub
      i64.const 24
      i64.div_s
      local.set 3
    end
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              local.get 4
              local.get 0
              i64.load32_u offset=8
              local.get 2
              i64.sub
              i64.const 24
              i64.div_s
              local.tee 2
              i64.const 1
              i64.shl
              local.tee 5
              local.get 5
              local.get 4
              i64.lt_u
              select
              i64.const 768614336404564650
              local.get 2
              i64.const 384307168202282325
              i64.lt_u
              select
              local.tee 4
              i64.eqz
              i32.eqz
              br_if 0 (;@5;)
              i32.const 0
              local.set 6
              br 1 (;@4;)
            end
            local.get 4
            i64.const 768614336404564651
            i64.ge_u
            br_if 1 (;@3;)
            local.get 4
            i64.const 24
            i64.mul
            call $operator_new_unsigned_long_
            local.set 6
          end
          local.get 1
          i64.load
          local.set 2
          local.get 1
          i64.const 0
          i64.store
          local.get 1
          i32.const 8
          i32.add
          local.tee 7
          i64.load
          local.set 5
          local.get 7
          i64.const 0
          i64.store
          local.get 1
          i32.const 16
          i32.add
          local.tee 1
          i64.load
          local.set 8
          local.get 1
          i64.const 0
          i64.store
          local.get 6
          local.get 3
          i32.wrap_i64
          i32.const 24
          i32.mul
          i32.add
          local.tee 7
          local.get 2
          i64.store
          local.get 7
          i32.const 16
          i32.add
          local.get 8
          i64.store
          local.get 7
          i32.const 8
          i32.add
          local.get 5
          i64.store
          local.get 6
          local.get 4
          i32.wrap_i64
          i32.const 24
          i32.mul
          i32.add
          local.set 9
          local.get 7
          i32.const 24
          i32.add
          local.set 10
          local.get 0
          i32.load offset=4
          local.tee 1
          local.get 0
          i32.load
          local.tee 11
          i32.eq
          br_if 1 (;@2;)
          loop  ;; label = @4
            local.get 7
            i32.const -24
            i32.add
            local.tee 7
            local.get 1
            i32.const -24
            i32.add
            local.tee 1
            i64.load
            i64.store
            local.get 7
            i32.const 16
            i32.add
            local.get 1
            i32.const 16
            i32.add
            local.tee 6
            i64.load
            i64.store
            local.get 7
            i32.const 8
            i32.add
            local.get 1
            i32.const 8
            i32.add
            local.tee 12
            i64.load
            i64.store
            local.get 1
            i64.const 0
            i64.store
            local.get 12
            i64.const 0
            i64.store
            local.get 6
            i64.const 0
            i64.store
            local.get 1
            local.get 11
            i32.ne
            br_if 0 (;@4;)
          end
          local.get 0
          local.get 9
          i32.store offset=8
          local.get 0
          i32.load offset=4
          local.set 1
          local.get 0
          local.get 10
          i32.store offset=4
          local.get 0
          i32.load
          local.set 11
          local.get 0
          local.get 7
          i32.store
          local.get 1
          local.get 11
          i32.eq
          br_if 2 (;@1;)
          loop  ;; label = @4
            local.get 1
            i32.const -24
            i32.add
            local.tee 1
            call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__
            local.get 1
            local.get 11
            i32.ne
            br_if 0 (;@4;)
            br 3 (;@1;)
          end
        end
        i64.const 8
        call $__cxa_allocate_exception
        local.tee 1
        call $std::bad_alloc::bad_alloc__
        local.get 1
        i32.const 0
        i32.const 2
        call $__cxa_throw
        unreachable
      end
      local.get 0
      local.get 9
      i32.store offset=8
      local.get 0
      local.get 10
      i32.store offset=4
      local.get 0
      local.get 7
      i32.store
    end
    block  ;; label = @1
      local.get 11
      i32.eqz
      br_if 0 (;@1;)
      local.get 11
      call $operator_delete_void*_
    end)
  (func $prf_F_void_const*__void_const*__unsigned_long_ (type 24) (param i32 i32 i32 i64)
    (local i32)
    local.get 1
    local.get 2
    local.get 3
    i32.wrap_i64
    local.get 3
    i64.const 28
    i64.add
    local.tee 3
    call $malloc
    local.tee 4
    i32.const 28
    i32.add
    i32.const 1268
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 4
    call $sgx_rijndael128GCM_encrypt
    drop
    local.get 4
    i32.const 24
    i32.add
    i32.const 0
    i32.load offset=1276 align=1
    i32.store align=1
    local.get 4
    i32.const 0
    i64.load offset=1268 align=1
    i64.store offset=16 align=1
    local.get 0
    local.get 3
    i64.store offset=8
    local.get 0
    local.get 4
    i32.store)
  (func $enc_aes_gcm_void_const*__void_const*__unsigned_long__void*_ (type 22) (param i32 i32 i64 i32)
    local.get 0
    local.get 1
    local.get 2
    i32.wrap_i64
    local.get 3
    i32.const 28
    i32.add
    i32.const 1268
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 3
    call $sgx_rijndael128GCM_encrypt
    drop
    local.get 3
    i32.const 24
    i32.add
    i32.const 0
    i32.load offset=1276 align=1
    i32.store align=1
    local.get 3
    i32.const 0
    i64.load offset=1268 align=1
    i64.store offset=16 align=1)
  (func $prf_Enc_void_const*__void_const*__unsigned_long_ (type 24) (param i32 i32 i32 i64)
    (local i32)
    local.get 1
    local.get 2
    local.get 3
    i32.wrap_i64
    local.get 3
    i64.const 28
    i64.add
    local.tee 3
    call $malloc
    local.tee 4
    i32.const 28
    i32.add
    i32.const 1268
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 4
    call $sgx_rijndael128GCM_encrypt
    drop
    local.get 4
    i32.const 24
    i32.add
    i32.const 0
    i32.load offset=1276 align=1
    i32.store align=1
    local.get 4
    i32.const 0
    i64.load offset=1268 align=1
    i64.store offset=16 align=1
    local.get 0
    local.get 3
    i64.store offset=8
    local.get 0
    local.get 4
    i32.store)
  (func $prf_Dec_void_const*__void_const*__unsigned_long_ (type 24) (param i32 i32 i32 i64)
    (local i32)
    local.get 1
    local.get 2
    i32.const 28
    i32.add
    local.get 3
    i64.const -28
    i64.add
    local.tee 3
    i32.wrap_i64
    local.get 3
    call $malloc
    local.tee 4
    i32.const 1268
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 2
    call $sgx_rijndael128GCM_decrypt
    drop
    local.get 0
    local.get 3
    i64.store offset=8
    local.get 0
    local.get 4
    i32.store)
  (func $dec_aes_gcm_void_const*__void_const*__unsigned_long__void*__unsigned_long_ (type 25) (param i32 i32 i64 i32 i64)
    local.get 0
    local.get 1
    i32.const 28
    i32.add
    local.get 4
    i32.wrap_i64
    local.get 3
    i32.const 1268
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 1
    call $sgx_rijndael128GCM_decrypt
    drop)
  (func $init_i_Array_i_Array*__unsigned_long_ (type 12) (param i32 i64)
    (local i32)
    local.get 1
    i64.const 2
    i64.shl
    call $malloc
    local.set 2
    local.get 0
    local.get 1
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    local.get 2
    i32.store)
  (func $insert_i_Array_i_Array*__int_ (type 10) (param i32 i32)
    (local i64 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i64.load offset=8
        local.tee 2
        local.get 0
        i64.load offset=16
        i64.eq
        br_if 0 (;@2;)
        local.get 0
        i32.load
        local.set 3
        br 1 (;@1;)
      end
      local.get 0
      local.get 2
      i64.const 1
      i64.shl
      i64.store offset=16
      local.get 0
      local.get 0
      i32.load
      local.get 2
      i64.const 3
      i64.shl
      call $realloc
      local.tee 3
      i32.store
      local.get 0
      i64.load offset=8
      local.set 2
    end
    local.get 0
    local.get 2
    i64.const 1
    i64.add
    i64.store offset=8
    local.get 3
    local.get 2
    i32.wrap_i64
    i32.const 2
    i32.shl
    i32.add
    local.get 1
    i32.store)
  (func $free_i_Array_i_Array*_ (type 3) (param i32)
    local.get 0
    i32.load
    call $free
    local.get 0
    i32.const 16
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i32.const 8
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i64.const 0
    i64.store)
  (func $init_uc_Array_uc_Array*__unsigned_long_ (type 12) (param i32 i64)
    (local i32)
    local.get 1
    call $malloc
    local.set 2
    local.get 0
    local.get 1
    i64.store offset=16
    local.get 0
    i64.const 0
    i64.store offset=8
    local.get 0
    local.get 2
    i32.store)
  (func $insert_uc_Array_uc_Array*__unsigned_char*__unsigned_long_ (type 8) (param i32 i32 i64)
    (local i64)
    block  ;; label = @1
      local.get 0
      i64.load offset=8
      local.tee 3
      local.get 0
      i64.load offset=16
      i64.ne
      br_if 0 (;@1;)
      local.get 0
      local.get 3
      i64.const 1
      i64.shl
      local.tee 3
      i64.store offset=16
      local.get 0
      local.get 0
      i32.load
      local.get 3
      call $realloc
      i32.store
      local.get 0
      i64.load offset=8
      local.set 3
    end
    local.get 0
    local.get 3
    i32.wrap_i64
    i32.const 24
    i32.mul
    i32.add
    local.get 1
    local.get 2
    i32.wrap_i64
    call $memcpy
    drop
    local.get 0
    local.get 0
    i64.load offset=8
    local.get 2
    i64.add
    i64.store offset=8)
  (func $free_uc_Array_uc_Array*_ (type 3) (param i32)
    local.get 0
    i32.load
    call $free
    local.get 0
    i32.const 16
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i32.const 8
    i32.add
    i64.const 0
    i64.store
    local.get 0
    i64.const 0
    i64.store)
  (table (;0;) 6 6 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 66912))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1312))
  (global (;3;) i32 (i32.const 1328))
  (global (;4;) i32 (i32.const 1024))
  (global (;5;) i32 (i32.const 1056))
  (global (;6;) i32 (i32.const 1368))
  (global (;7;) i32 (i32.const 1024))
  (global (;8;) i32 (i32.const 66912))
  (global (;9;) i32 (i32.const 0))
  (global (;10;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "ecall_init" (func $ecall_init))
  (export "ecall_query_keyword" (func $ecall_query_keyword))
  (export "ecall_update_doc" (func $ecall_update_doc))
  (export "ocall_print_int" (func $ocall_print_int))
  (export "ocall_print_string" (func $ocall_print_string))
  (export "ocall_get_docId" (func $ocall_get_docId))
  (export "ocall_get_delId" (func $ocall_get_delId))
  (export "ocall_send_to_client" (func $ocall_send_to_client))
  (export "ocall_transfer_updated_entries" (func $ocall_transfer_updated_entries))
  (export "sgx_oc_cpuidex" (func $sgx_oc_cpuidex))
  (export "sgx_thread_wait_untrusted_event_ocall" (func $sgx_thread_wait_untrusted_event_ocall))
  (export "sgx_thread_set_untrusted_event_ocall" (func $sgx_thread_set_untrusted_event_ocall))
  (export "sgx_thread_setwait_untrusted_events_ocall" (func $sgx_thread_setwait_untrusted_events_ocall))
  (export "sgx_thread_set_multiple_untrusted_events_ocall" (func $sgx_thread_set_multiple_untrusted_events_ocall))
  (export "__dso_handle" (global 1))
  (export "KW" (global 2))
  (export "KI" (global 3))
  (export "_Z13prf_F_improvePKvS0_mP6rand_t" (func $prf_F_improve_void_const*__void_const*__unsigned_long__rand_t*_))
  (export "_Z15prf_Dec_improvePKvS0_mP6rand_t" (func $prf_Dec_improve_void_const*__void_const*__unsigned_long__rand_t*_))
  (export "_ZNSt3__116__set_differenceIRNS_6__lessINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_EEPS7_SA_NS_20back_insert_iteratorINS_6vectorIS7_NS5_IS7_EEEEEEEET2_T0_SH_T1_SI_SG_T_" (func $std::__1::back_insert_iterator<std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>_>_std::__1::__set_difference<std::__1::__less<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>&__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::back_insert_iterator<std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>_>_>_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>*__std::__1::back_insert_iterator<std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>_>__std::__1::__less<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>&_))
  (export "_Z15prf_Enc_improvePKvS0_mP6rand_t" (func $prf_Enc_improve_void_const*__void_const*__unsigned_long__rand_t*_))
  (export "__clang_call_terminate" (func $__clang_call_terminate))
  (export "_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIRKS6_EEvOT_" (func $void_std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>::__push_back_slow_path<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&>_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&_))
  (export "_ZNSt3__113__vector_baseINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEED2Ev" (func $std::__1::__vector_base<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>::~__vector_base__))
  (export "_ZNSt3__114__split_bufferINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEERNS4_IS6_EEED2Ev" (func $std::__1::__split_buffer<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>&>::~__split_buffer__))
  (export "_Z6printfPKcz" (func $printf_char_const*__..._))
  (export "_Z11print_bytesPhj" (func $print_bytes_unsigned_char*__unsigned_int_))
  (export "_Z3cmpPKhS0_j" (func $cmp_unsigned_char_const*__unsigned_char_const*__unsigned_int_))
  (export "_Z5clearPhj" (func $clear_unsigned_char*__unsigned_int_))
  (export "_Z12wordTokenizePci" (func $wordTokenize_char*__int_))
  (export "_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE21__push_back_slow_pathIS6_EEvOT_" (func $void_std::__1::vector<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>__std::__1::allocator<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_>::__push_back_slow_path<std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_>_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>&&_))
  (export "_Z5prf_FPKvS0_m" (func $prf_F_void_const*__void_const*__unsigned_long_))
  (export "_Z11enc_aes_gcmPKvS0_mPv" (func $enc_aes_gcm_void_const*__void_const*__unsigned_long__void*_))
  (export "_Z7prf_EncPKvS0_m" (func $prf_Enc_void_const*__void_const*__unsigned_long_))
  (export "_Z7prf_DecPKvS0_m" (func $prf_Dec_void_const*__void_const*__unsigned_long_))
  (export "_Z11dec_aes_gcmPKvS0_mPvm" (func $dec_aes_gcm_void_const*__void_const*__unsigned_long__void*__unsigned_long_))
  (export "_Z12init_i_ArrayP7i_Arraym" (func $init_i_Array_i_Array*__unsigned_long_))
  (export "_Z14insert_i_ArrayP7i_Arrayi" (func $insert_i_Array_i_Array*__int_))
  (export "_Z12free_i_ArrayP7i_Array" (func $free_i_Array_i_Array*_))
  (export "_Z13init_uc_ArrayP8uc_Arraym" (func $init_uc_Array_uc_Array*__unsigned_long_))
  (export "_Z15insert_uc_ArrayP8uc_ArrayPhm" (func $insert_uc_Array_uc_Array*__unsigned_char*__unsigned_long_))
  (export "_Z13free_uc_ArrayP8uc_Array" (func $free_uc_Array_uc_Array*_))
  (export "g_ecall_table" (global 4))
  (export "g_dyn_entry_table" (global 5))
  (export "__indirect_function_table" (table 0))
  (export "__data_end" (global 6))
  (export "__global_base" (global 7))
  (export "__heap_base" (global 8))
  (export "__memory_base" (global 9))
  (export "__table_base" (global 10))
  (elem (;0;) (i32.const 1) func $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::~basic_string__ $std::bad_alloc::~bad_alloc__ $sgx_ecall_init $sgx_ecall_query_keyword $sgx_ecall_update_doc)
  (data $.rodata (i32.const 1024) "\03\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\04\00\00\00\00\00\00\00\05\00\00\00\00\00\00\00\0b\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00%x\00__n == 0 || __s != nullptr\00/opt/intel/sgxsdk/include/libcxx/vector\00basic_string\00/opt/intel/sgxsdk/include/libcxx/string\00operator[]\00streaming/\00__n < size()\00\0a\00\01\00\00\00")
  (data $.data (i32.const 1268) "\99\aa>h\ed\81s\a0\ee\d0f\84"))
