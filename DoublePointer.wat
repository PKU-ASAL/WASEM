(module
  (type (;0;) (func (param i32 i32) (result i32)))
  (type (;1;) (func))
  (type (;2;) (func (param i32) (result i32)))
  (type (;3;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;4;) (func (param i32 i32 i32) (result i32)))
  (type (;5;) (func (param i32 i64 i64) (result i32)))
  (type (;6;) (func (result i32)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "__builtin_ia32_lfence" (func $__builtin_ia32_lfence (type 1)))
  (import "env" "strlen" (func $strlen (type 2)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 2)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 1)))
  (import "env" "memcpy_s" (func $memcpy_s (type 3)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 0)))
  (import "env" "memset" (func $memset (type 4)))
  (import "env" "vsnprintf" (func $vsnprintf (type 3)))
  (import "env" "strnlen" (func $strnlen (type 0)))
  (import "env" "abort" (func $abort (type 1)))
  (func $__wasm_call_ctors (type 1))
  (func $sgx_ecall_allocate_buffers (type 2) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 1
    i32.const 16
    local.set 2
    local.get 1
    local.get 2
    i32.sub
    local.set 3
    local.get 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=8
    local.get 3
    i32.load offset=8
    local.set 4
    i32.const 0
    local.set 5
    local.get 4
    local.set 6
    local.get 5
    local.set 7
    local.get 6
    local.get 7
    i32.ne
    local.set 8
    i32.const 1
    local.set 9
    local.get 8
    local.get 9
    i32.and
    local.set 10
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 10
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=8
          local.set 11
          i32.const 4
          local.set 12
          local.get 11
          local.get 12
          call $sgx_is_outside_enclave
          local.set 13
          local.get 13
          br_if 1 (;@2;)
        end
        i32.const 2
        local.set 14
        local.get 3
        local.get 14
        i32.store offset=12
        br 1 (;@1;)
      end
      call $__builtin_ia32_lfence
      local.get 3
      i32.load offset=8
      local.set 15
      local.get 3
      local.get 15
      i32.store offset=4
      i32.const 0
      local.set 16
      local.get 3
      local.get 16
      i32.store
      call $ecall_allocate_buffers
      local.set 17
      local.get 3
      i32.load offset=4
      local.set 18
      local.get 18
      local.get 17
      i32.store
      local.get 3
      i32.load
      local.set 19
      local.get 3
      local.get 19
      i32.store offset=12
    end
    local.get 3
    i32.load offset=12
    local.set 20
    i32.const 16
    local.set 21
    local.get 3
    local.get 21
    i32.add
    local.set 22
    local.get 22
    global.set $__stack_pointer
    local.get 20
    return)
  (func $sgx_ecall_allocate_buffers_safe (type 2) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 1
    i32.const 16
    local.set 2
    local.get 1
    local.get 2
    i32.sub
    local.set 3
    local.get 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=8
    local.get 3
    i32.load offset=8
    local.set 4
    i32.const 0
    local.set 5
    local.get 4
    local.set 6
    local.get 5
    local.set 7
    local.get 6
    local.get 7
    i32.ne
    local.set 8
    i32.const 1
    local.set 9
    local.get 8
    local.get 9
    i32.and
    local.set 10
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 10
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=8
          local.set 11
          i32.const 4
          local.set 12
          local.get 11
          local.get 12
          call $sgx_is_outside_enclave
          local.set 13
          local.get 13
          br_if 1 (;@2;)
        end
        i32.const 2
        local.set 14
        local.get 3
        local.get 14
        i32.store offset=12
        br 1 (;@1;)
      end
      call $__builtin_ia32_lfence
      local.get 3
      i32.load offset=8
      local.set 15
      local.get 3
      local.get 15
      i32.store offset=4
      i32.const 0
      local.set 16
      local.get 3
      local.get 16
      i32.store
      call $ecall_allocate_buffers_safe
      local.set 17
      local.get 3
      i32.load offset=4
      local.set 18
      local.get 18
      local.get 17
      i32.store
      local.get 3
      i32.load
      local.set 19
      local.get 3
      local.get 19
      i32.store offset=12
    end
    local.get 3
    i32.load offset=12
    local.set 20
    i32.const 16
    local.set 21
    local.get 3
    local.get 21
    i32.add
    local.set 22
    local.get 22
    global.set $__stack_pointer
    local.get 20
    return)
  (func $ocall_print_string (type 2) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 1
    i32.const 32
    local.set 2
    local.get 1
    local.get 2
    i32.sub
    local.set 3
    local.get 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=24
    i32.const 0
    local.set 4
    local.get 3
    local.get 4
    i32.store offset=20
    local.get 3
    i32.load offset=24
    local.set 5
    i32.const 0
    local.set 6
    local.get 5
    local.set 7
    local.get 6
    local.set 8
    local.get 7
    local.get 8
    i32.ne
    local.set 9
    i32.const 1
    local.set 10
    local.get 9
    local.get 10
    i32.and
    local.set 11
    block  ;; label = @1
      block  ;; label = @2
        local.get 11
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=24
        local.set 12
        local.get 12
        call $strlen
        local.set 13
        i32.const 1
        local.set 14
        local.get 13
        local.get 14
        i32.add
        local.set 15
        local.get 15
        local.set 16
        br 1 (;@1;)
      end
      i32.const 0
      local.set 17
      local.get 17
      local.set 16
    end
    local.get 16
    local.set 18
    local.get 3
    local.get 18
    i32.store offset=16
    i32.const 0
    local.set 19
    local.get 3
    local.get 19
    i32.store offset=12
    i32.const 4
    local.set 20
    local.get 3
    local.get 20
    i32.store offset=8
    i32.const 0
    local.set 21
    local.get 3
    local.get 21
    i32.store offset=4
    local.get 3
    i32.load offset=24
    local.set 22
    i32.const 0
    local.set 23
    local.get 22
    local.set 24
    local.get 23
    local.set 25
    local.get 24
    local.get 25
    i32.ne
    local.set 26
    i32.const 1
    local.set 27
    local.get 26
    local.get 27
    i32.and
    local.set 28
    block  ;; label = @1
      block  ;; label = @2
        local.get 28
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=24
        local.set 29
        local.get 3
        i32.load offset=16
        local.set 30
        local.get 29
        local.get 30
        call $sgx_is_within_enclave
        local.set 31
        local.get 31
        br_if 0 (;@2;)
        i32.const 2
        local.set 32
        local.get 3
        local.get 32
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=24
      local.set 33
      i32.const 0
      local.set 34
      local.get 33
      local.set 35
      local.get 34
      local.set 36
      local.get 35
      local.get 36
      i32.ne
      local.set 37
      i32.const 1
      local.set 38
      local.get 37
      local.get 38
      i32.and
      local.set 39
      block  ;; label = @2
        block  ;; label = @3
          local.get 39
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=16
          local.set 40
          local.get 40
          local.set 41
          br 1 (;@2;)
        end
        i32.const 0
        local.set 42
        local.get 42
        local.set 41
      end
      local.get 41
      local.set 43
      local.get 3
      i32.load offset=8
      local.set 44
      local.get 44
      local.get 43
      i32.add
      local.set 45
      local.get 3
      local.get 45
      i32.store offset=8
      local.get 3
      i32.load offset=24
      local.set 46
      i32.const 0
      local.set 47
      local.get 46
      local.set 48
      local.get 47
      local.set 49
      local.get 48
      local.get 49
      i32.ne
      local.set 50
      i32.const 1
      local.set 51
      local.get 50
      local.get 51
      i32.and
      local.set 52
      block  ;; label = @2
        block  ;; label = @3
          local.get 52
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=16
          local.set 53
          local.get 53
          local.set 54
          br 1 (;@2;)
        end
        i32.const 0
        local.set 55
        local.get 55
        local.set 54
      end
      local.get 54
      local.set 56
      local.get 45
      local.set 57
      local.get 56
      local.set 58
      local.get 57
      local.get 58
      i32.lt_u
      local.set 59
      i32.const 1
      local.set 60
      local.get 59
      local.get 60
      i32.and
      local.set 61
      block  ;; label = @2
        local.get 61
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2
        local.set 62
        local.get 3
        local.get 62
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=8
      local.set 63
      local.get 63
      call $sgx_ocalloc
      local.set 64
      local.get 3
      local.get 64
      i32.store offset=4
      local.get 3
      i32.load offset=4
      local.set 65
      i32.const 0
      local.set 66
      local.get 65
      local.set 67
      local.get 66
      local.set 68
      local.get 67
      local.get 68
      i32.eq
      local.set 69
      i32.const 1
      local.set 70
      local.get 69
      local.get 70
      i32.and
      local.set 71
      block  ;; label = @2
        local.get 71
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        i32.const 1
        local.set 72
        local.get 3
        local.get 72
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=4
      local.set 73
      local.get 3
      local.get 73
      i32.store offset=12
      local.get 3
      i32.load offset=4
      local.set 74
      i32.const 4
      local.set 75
      local.get 74
      local.get 75
      i32.add
      local.set 76
      local.get 3
      local.get 76
      i32.store offset=4
      local.get 3
      i32.load offset=8
      local.set 77
      i32.const 4
      local.set 78
      local.get 77
      local.get 78
      i32.sub
      local.set 79
      local.get 3
      local.get 79
      i32.store offset=8
      local.get 3
      i32.load offset=24
      local.set 80
      i32.const 0
      local.set 81
      local.get 80
      local.set 82
      local.get 81
      local.set 83
      local.get 82
      local.get 83
      i32.ne
      local.set 84
      i32.const 1
      local.set 85
      local.get 84
      local.get 85
      i32.and
      local.set 86
      block  ;; label = @2
        block  ;; label = @3
          local.get 86
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=4
          local.set 87
          local.get 3
          i32.load offset=12
          local.set 88
          local.get 88
          local.get 87
          i32.store
          local.get 3
          i32.load offset=16
          local.set 89
          i32.const 0
          local.set 90
          local.get 89
          local.get 90
          i32.and
          local.set 91
          block  ;; label = @4
            local.get 91
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            i32.const 2
            local.set 92
            local.get 3
            local.get 92
            i32.store offset=28
            br 3 (;@1;)
          end
          local.get 3
          i32.load offset=4
          local.set 93
          local.get 3
          i32.load offset=8
          local.set 94
          local.get 3
          i32.load offset=24
          local.set 95
          local.get 3
          i32.load offset=16
          local.set 96
          local.get 93
          local.get 94
          local.get 95
          local.get 96
          call $memcpy_s
          local.set 97
          block  ;; label = @4
            local.get 97
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            i32.const 1
            local.set 98
            local.get 3
            local.get 98
            i32.store offset=28
            br 3 (;@1;)
          end
          local.get 3
          i32.load offset=4
          local.set 99
          local.get 3
          i32.load offset=16
          local.set 100
          local.get 99
          local.get 100
          i32.add
          local.set 101
          local.get 3
          local.get 101
          i32.store offset=4
          local.get 3
          i32.load offset=16
          local.set 102
          local.get 3
          i32.load offset=8
          local.set 103
          local.get 103
          local.get 102
          i32.sub
          local.set 104
          local.get 3
          local.get 104
          i32.store offset=8
          br 1 (;@2;)
        end
        local.get 3
        i32.load offset=12
        local.set 105
        i32.const 0
        local.set 106
        local.get 105
        local.get 106
        i32.store
      end
      local.get 3
      i32.load offset=12
      local.set 107
      i32.const 0
      local.set 108
      local.get 108
      local.get 107
      call $sgx_ocall
      local.set 109
      local.get 3
      local.get 109
      i32.store offset=20
      local.get 3
      i32.load offset=20
      local.set 110
      block  ;; label = @2
        local.get 110
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 3
      i32.load offset=20
      local.set 111
      local.get 3
      local.get 111
      i32.store offset=28
    end
    local.get 3
    i32.load offset=28
    local.set 112
    i32.const 32
    local.set 113
    local.get 3
    local.get 113
    i32.add
    local.set 114
    local.get 114
    global.set $__stack_pointer
    local.get 112
    return)
  (func $ocall_enc_untrusted_allocate_buffers (type 5) (param i32 i64 i64) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i64 i32 i64 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 3
    i32.const 48
    local.set 4
    local.get 3
    local.get 4
    i32.sub
    local.set 5
    local.get 5
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
    i32.const 0
    local.set 6
    local.get 5
    local.get 6
    i32.store offset=20
    i32.const 0
    local.set 7
    local.get 5
    local.get 7
    i32.store offset=16
    i32.const 24
    local.set 8
    local.get 5
    local.get 8
    i32.store offset=12
    i32.const 0
    local.set 9
    local.get 5
    local.get 9
    i32.store offset=8
    local.get 5
    i32.load offset=12
    local.set 10
    local.get 10
    call $sgx_ocalloc
    local.set 11
    local.get 5
    local.get 11
    i32.store offset=8
    local.get 5
    i32.load offset=8
    local.set 12
    i32.const 0
    local.set 13
    local.get 12
    local.set 14
    local.get 13
    local.set 15
    local.get 14
    local.get 15
    i32.eq
    local.set 16
    i32.const 1
    local.set 17
    local.get 16
    local.get 17
    i32.and
    local.set 18
    block  ;; label = @1
      block  ;; label = @2
        local.get 18
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        i32.const 1
        local.set 19
        local.get 5
        local.get 19
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 5
      i32.load offset=8
      local.set 20
      local.get 5
      local.get 20
      i32.store offset=16
      local.get 5
      i32.load offset=8
      local.set 21
      i32.const 24
      local.set 22
      local.get 21
      local.get 22
      i32.add
      local.set 23
      local.get 5
      local.get 23
      i32.store offset=8
      local.get 5
      i32.load offset=12
      local.set 24
      i32.const 24
      local.set 25
      local.get 24
      local.get 25
      i32.sub
      local.set 26
      local.get 5
      local.get 26
      i32.store offset=12
      local.get 5
      i64.load offset=32
      local.set 27
      local.get 5
      i32.load offset=16
      local.set 28
      local.get 28
      local.get 27
      i64.store offset=8
      local.get 5
      i64.load offset=24
      local.set 29
      local.get 5
      i32.load offset=16
      local.set 30
      local.get 30
      local.get 29
      i64.store offset=16
      local.get 5
      i32.load offset=16
      local.set 31
      i32.const 1
      local.set 32
      local.get 32
      local.get 31
      call $sgx_ocall
      local.set 33
      local.get 5
      local.get 33
      i32.store offset=20
      local.get 5
      i32.load offset=20
      local.set 34
      block  ;; label = @2
        local.get 34
        br_if 0 (;@2;)
        local.get 5
        i32.load offset=40
        local.set 35
        i32.const 0
        local.set 36
        local.get 35
        local.set 37
        local.get 36
        local.set 38
        local.get 37
        local.get 38
        i32.ne
        local.set 39
        i32.const 1
        local.set 40
        local.get 39
        local.get 40
        i32.and
        local.set 41
        block  ;; label = @3
          local.get 41
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=16
          local.set 42
          local.get 42
          i32.load
          local.set 43
          local.get 5
          i32.load offset=40
          local.set 44
          local.get 44
          local.get 43
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 5
      i32.load offset=20
      local.set 45
      local.get 5
      local.get 45
      i32.store offset=44
    end
    local.get 5
    i32.load offset=44
    local.set 46
    i32.const 48
    local.set 47
    local.get 5
    local.get 47
    i32.add
    local.set 48
    local.get 48
    global.set $__stack_pointer
    local.get 46
    return)
  (func $ocall_untrusted_local_free (type 2) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 1
    i32.const 32
    local.set 2
    local.get 1
    local.get 2
    i32.sub
    local.set 3
    local.get 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=24
    i32.const 0
    local.set 4
    local.get 3
    local.get 4
    i32.store offset=20
    i32.const 0
    local.set 5
    local.get 3
    local.get 5
    i32.store offset=16
    i32.const 4
    local.set 6
    local.get 3
    local.get 6
    i32.store offset=12
    i32.const 0
    local.set 7
    local.get 3
    local.get 7
    i32.store offset=8
    local.get 3
    i32.load offset=12
    local.set 8
    local.get 8
    call $sgx_ocalloc
    local.set 9
    local.get 3
    local.get 9
    i32.store offset=8
    local.get 3
    i32.load offset=8
    local.set 10
    i32.const 0
    local.set 11
    local.get 10
    local.set 12
    local.get 11
    local.set 13
    local.get 12
    local.get 13
    i32.eq
    local.set 14
    i32.const 1
    local.set 15
    local.get 14
    local.get 15
    i32.and
    local.set 16
    block  ;; label = @1
      block  ;; label = @2
        local.get 16
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        i32.const 1
        local.set 17
        local.get 3
        local.get 17
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=8
      local.set 18
      local.get 3
      local.get 18
      i32.store offset=16
      local.get 3
      i32.load offset=8
      local.set 19
      i32.const 4
      local.set 20
      local.get 19
      local.get 20
      i32.add
      local.set 21
      local.get 3
      local.get 21
      i32.store offset=8
      local.get 3
      i32.load offset=12
      local.set 22
      i32.const 4
      local.set 23
      local.get 22
      local.get 23
      i32.sub
      local.set 24
      local.get 3
      local.get 24
      i32.store offset=12
      local.get 3
      i32.load offset=24
      local.set 25
      local.get 3
      i32.load offset=16
      local.set 26
      local.get 26
      local.get 25
      i32.store
      local.get 3
      i32.load offset=16
      local.set 27
      i32.const 2
      local.set 28
      local.get 28
      local.get 27
      call $sgx_ocall
      local.set 29
      local.get 3
      local.get 29
      i32.store offset=20
      local.get 3
      i32.load offset=20
      local.set 30
      block  ;; label = @2
        local.get 30
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 3
      i32.load offset=20
      local.set 31
      local.get 3
      local.get 31
      i32.store offset=28
    end
    local.get 3
    i32.load offset=28
    local.set 32
    i32.const 32
    local.set 33
    local.get 3
    local.get 33
    i32.add
    local.set 34
    local.get 34
    global.set $__stack_pointer
    local.get 32
    return)
  (func $printf (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 2
    i32.const 8224
    local.set 3
    local.get 2
    local.get 3
    i32.sub
    local.set 4
    local.get 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=8220
    i32.const 16
    local.set 5
    local.get 4
    local.get 5
    i32.add
    local.set 6
    local.get 6
    local.set 7
    i32.const 8192
    local.set 8
    i32.const 0
    local.set 9
    local.get 7
    local.get 9
    local.get 8
    call $memset
    drop
    i32.const 12
    local.set 10
    local.get 4
    local.get 10
    i32.add
    local.set 11
    local.get 11
    local.set 12
    local.get 12
    local.get 1
    i32.store
    i32.const 16
    local.set 13
    local.get 4
    local.get 13
    i32.add
    local.set 14
    local.get 14
    local.set 15
    local.get 4
    i32.load offset=8220
    local.set 16
    local.get 4
    i32.load offset=12
    local.set 17
    i32.const 8192
    local.set 18
    local.get 15
    local.get 18
    local.get 16
    local.get 17
    call $vsnprintf
    drop
    i32.const 12
    local.set 19
    local.get 4
    local.get 19
    i32.add
    local.set 20
    local.get 20
    drop
    i32.const 16
    local.set 21
    local.get 4
    local.get 21
    i32.add
    local.set 22
    local.get 22
    local.set 23
    local.get 23
    call $ocall_print_string
    drop
    i32.const 16
    local.set 24
    local.get 4
    local.get 24
    i32.add
    local.set 25
    local.get 25
    local.set 26
    i32.const 8191
    local.set 27
    local.get 26
    local.get 27
    call $strnlen
    local.set 28
    i32.const 1
    local.set 29
    local.get 28
    local.get 29
    i32.add
    local.set 30
    i32.const 8224
    local.set 31
    local.get 4
    local.get 31
    i32.add
    local.set 32
    local.get 32
    global.set $__stack_pointer
    local.get 30
    return)
  (func $allocate_untrusted_buffers_unsigned_long__unsigned_long_ (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i64 i32 i32 i64 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 2
    i32.const 32
    local.set 3
    local.get 2
    local.get 3
    i32.sub
    local.set 4
    local.get 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=28
    local.get 4
    local.get 1
    i32.store offset=24
    i32.const 1
    local.set 5
    local.get 4
    local.get 5
    i32.store offset=16
    local.get 4
    i32.load offset=28
    local.set 6
    local.get 6
    local.set 7
    local.get 7
    i64.extend_i32_u
    local.set 8
    local.get 4
    i32.load offset=24
    local.set 9
    local.get 9
    local.set 10
    local.get 10
    i64.extend_i32_u
    local.set 11
    i32.const 20
    local.set 12
    local.get 4
    local.get 12
    i32.add
    local.set 13
    local.get 13
    local.set 14
    local.get 14
    local.get 8
    local.get 11
    call $ocall_enc_untrusted_allocate_buffers
    local.set 15
    local.get 4
    local.get 15
    i32.store offset=16
    local.get 4
    i32.load offset=16
    local.set 16
    block  ;; label = @1
      block  ;; label = @2
        local.get 16
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=20
        local.set 17
        local.get 4
        i32.load offset=28
        local.set 18
        i32.const 2
        local.set 19
        local.get 18
        local.get 19
        i32.shl
        local.set 20
        local.get 17
        local.get 20
        call $sgx_is_outside_enclave
        local.set 21
        local.get 21
        br_if 1 (;@1;)
      end
      i32.const 37
      local.set 22
      local.get 4
      local.get 22
      i32.store offset=4
      i32.const 1056
      local.set 23
      local.get 4
      local.get 23
      i32.store
      i32.const 1121
      local.set 24
      local.get 24
      local.get 4
      call $printf
      drop
      call $abort
      unreachable
    end
    local.get 4
    i32.load offset=20
    local.set 25
    i32.const 32
    local.set 26
    local.get 4
    local.get 26
    i32.add
    local.set 27
    local.get 27
    global.set $__stack_pointer
    local.get 25
    return)
  (func $init_buffers__ (type 1)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 0
    i32.const 16
    local.set 1
    local.get 0
    local.get 1
    i32.sub
    local.set 2
    local.get 2
    global.set $__stack_pointer
    i32.const 0
    local.set 3
    local.get 2
    local.get 3
    i32.store offset=12
    i32.const 16
    local.set 4
    i32.const 8
    local.set 5
    local.get 4
    local.get 5
    call $allocate_untrusted_buffers_unsigned_long__unsigned_long_
    local.set 6
    local.get 2
    local.get 6
    i32.store offset=12
    local.get 2
    i32.load offset=12
    local.set 7
    i32.const 0
    local.set 8
    local.get 7
    local.set 9
    local.get 8
    local.set 10
    local.get 9
    local.get 10
    i32.eq
    local.set 11
    i32.const 1
    local.set 12
    local.get 11
    local.get 12
    i32.and
    local.set 13
    block  ;; label = @1
      local.get 13
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    i32.const 0
    local.set 14
    local.get 2
    local.get 14
    i32.store offset=8
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        i32.load offset=8
        local.set 15
        i32.const 16
        local.set 16
        local.get 15
        local.set 17
        local.get 16
        local.set 18
        local.get 17
        local.get 18
        i32.lt_s
        local.set 19
        i32.const 1
        local.set 20
        local.get 19
        local.get 20
        i32.and
        local.set 21
        local.get 21
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
        i32.load offset=12
        local.set 22
        local.get 2
        i32.load offset=8
        local.set 23
        i32.const 2
        local.set 24
        local.get 23
        local.get 24
        i32.shl
        local.set 25
        local.get 22
        local.get 25
        i32.add
        local.set 26
        local.get 26
        i32.load
        local.set 27
        i32.const 0
        local.set 28
        local.get 27
        local.set 29
        local.get 28
        local.set 30
        local.get 29
        local.get 30
        i32.ne
        local.set 31
        i32.const 1
        local.set 32
        local.get 31
        local.get 32
        i32.and
        local.set 33
        block  ;; label = @3
          block  ;; label = @4
            local.get 33
            i32.eqz
            br_if 0 (;@4;)
            local.get 2
            i32.load offset=12
            local.set 34
            local.get 2
            i32.load offset=8
            local.set 35
            i32.const 2
            local.set 36
            local.get 35
            local.get 36
            i32.shl
            local.set 37
            local.get 34
            local.get 37
            i32.add
            local.set 38
            local.get 38
            i32.load
            local.set 39
            i32.const 8
            local.set 40
            local.get 39
            local.get 40
            call $sgx_is_outside_enclave
            local.set 41
            local.get 41
            br_if 1 (;@3;)
          end
          i32.const 55
          local.set 42
          local.get 2
          local.get 42
          i32.store offset=4
          i32.const 1056
          local.set 43
          local.get 2
          local.get 43
          i32.store
          i32.const 1121
          local.set 44
          local.get 44
          local.get 2
          call $printf
          drop
          call $abort
          unreachable
        end
        local.get 2
        i32.load offset=12
        local.set 45
        local.get 2
        i32.load offset=8
        local.set 46
        i32.const 2
        local.set 47
        local.get 46
        local.get 47
        i32.shl
        local.set 48
        local.get 45
        local.get 48
        i32.add
        local.set 49
        local.get 49
        i32.load
        local.set 50
        local.get 2
        i32.load offset=8
        local.set 51
        i32.const 1152
        local.set 52
        i32.const 2
        local.set 53
        local.get 51
        local.get 53
        i32.shl
        local.set 54
        local.get 52
        local.get 54
        i32.add
        local.set 55
        local.get 55
        local.get 50
        i32.store
        local.get 2
        i32.load offset=8
        local.set 56
        i32.const 1
        local.set 57
        local.get 56
        local.get 57
        i32.add
        local.set 58
        local.get 2
        local.get 58
        i32.store offset=8
        br 0 (;@2;)
      end
    end
    local.get 2
    i32.load offset=12
    local.set 59
    local.get 59
    call $ocall_untrusted_local_free
    drop
    i32.const 16
    local.set 60
    local.get 2
    local.get 60
    i32.add
    local.set 61
    local.get 61
    global.set $__stack_pointer
    return)
  (func $init_buffers_safe__ (type 1)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 0
    i32.const 32
    local.set 1
    local.get 0
    local.get 1
    i32.sub
    local.set 2
    local.get 2
    global.set $__stack_pointer
    i32.const 0
    local.set 3
    local.get 2
    local.get 3
    i32.store offset=28
    i32.const 16
    local.set 4
    i32.const 8
    local.set 5
    local.get 4
    local.get 5
    call $allocate_untrusted_buffers_unsigned_long__unsigned_long_
    local.set 6
    local.get 2
    local.get 6
    i32.store offset=28
    local.get 2
    i32.load offset=28
    local.set 7
    i32.const 0
    local.set 8
    local.get 7
    local.set 9
    local.get 8
    local.set 10
    local.get 9
    local.get 10
    i32.eq
    local.set 11
    i32.const 1
    local.set 12
    local.get 11
    local.get 12
    i32.and
    local.set 13
    block  ;; label = @1
      local.get 13
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    i32.const 0
    local.set 14
    local.get 2
    local.get 14
    i32.store offset=24
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        i32.load offset=24
        local.set 15
        i32.const 16
        local.set 16
        local.get 15
        local.set 17
        local.get 16
        local.set 18
        local.get 17
        local.get 18
        i32.lt_s
        local.set 19
        i32.const 1
        local.set 20
        local.get 19
        local.get 20
        i32.and
        local.set 21
        local.get 21
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
        i32.load offset=28
        local.set 22
        local.get 2
        i32.load offset=24
        local.set 23
        i32.const 2
        local.set 24
        local.get 23
        local.get 24
        i32.shl
        local.set 25
        local.get 22
        local.get 25
        i32.add
        local.set 26
        local.get 26
        i32.load
        local.set 27
        local.get 2
        local.get 27
        i32.store offset=20
        local.get 2
        i32.load offset=20
        local.set 28
        i32.const 0
        local.set 29
        local.get 28
        local.set 30
        local.get 29
        local.set 31
        local.get 30
        local.get 31
        i32.ne
        local.set 32
        i32.const 1
        local.set 33
        local.get 32
        local.get 33
        i32.and
        local.set 34
        block  ;; label = @3
          block  ;; label = @4
            local.get 34
            i32.eqz
            br_if 0 (;@4;)
            local.get 2
            i32.load offset=20
            local.set 35
            i32.const 8
            local.set 36
            local.get 35
            local.get 36
            call $sgx_is_outside_enclave
            local.set 37
            local.get 37
            br_if 1 (;@3;)
          end
          i32.const 77
          local.set 38
          local.get 2
          local.get 38
          i32.store offset=4
          i32.const 1056
          local.set 39
          local.get 2
          local.get 39
          i32.store
          i32.const 1121
          local.set 40
          local.get 40
          local.get 2
          call $printf
          drop
          call $abort
          unreachable
        end
        local.get 2
        i32.load offset=20
        local.set 41
        local.get 2
        i32.load offset=24
        local.set 42
        i32.const 1152
        local.set 43
        i32.const 2
        local.set 44
        local.get 42
        local.get 44
        i32.shl
        local.set 45
        local.get 43
        local.get 45
        i32.add
        local.set 46
        local.get 46
        local.get 41
        i32.store
        local.get 2
        i32.load offset=24
        local.set 47
        i32.const 1
        local.set 48
        local.get 47
        local.get 48
        i32.add
        local.set 49
        local.get 2
        local.get 49
        i32.store offset=24
        br 0 (;@2;)
      end
    end
    local.get 2
    i32.load offset=28
    local.set 50
    local.get 50
    call $ocall_untrusted_local_free
    drop
    i32.const 32
    local.set 51
    local.get 2
    local.get 51
    i32.add
    local.set 52
    local.get 52
    global.set $__stack_pointer
    return)
  (func $free_buffers__ (type 1)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 0
    i32.const 16
    local.set 1
    local.get 0
    local.get 1
    i32.sub
    local.set 2
    local.get 2
    global.set $__stack_pointer
    i32.const 1152
    local.set 3
    local.get 2
    local.get 3
    i32.store offset=12
    i32.const 1152
    local.set 4
    local.get 2
    local.get 4
    i32.store offset=8
    i32.const 1152
    local.set 5
    i32.const 64
    local.set 6
    local.get 5
    local.get 6
    i32.add
    local.set 7
    local.get 2
    local.get 7
    i32.store offset=4
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        i32.load offset=8
        local.set 8
        local.get 2
        i32.load offset=4
        local.set 9
        local.get 8
        local.set 10
        local.get 9
        local.set 11
        local.get 10
        local.get 11
        i32.ne
        local.set 12
        i32.const 1
        local.set 13
        local.get 12
        local.get 13
        i32.and
        local.set 14
        local.get 14
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
        i32.load offset=8
        local.set 15
        local.get 2
        local.get 15
        i32.store
        local.get 2
        i32.load
        local.set 16
        local.get 16
        i32.load
        local.set 17
        local.get 17
        call $ocall_untrusted_local_free
        drop
        local.get 2
        i32.load offset=8
        local.set 18
        i32.const 4
        local.set 19
        local.get 18
        local.get 19
        i32.add
        local.set 20
        local.get 2
        local.get 20
        i32.store offset=8
        br 0 (;@2;)
      end
    end
    i32.const 16
    local.set 21
    local.get 2
    local.get 21
    i32.add
    local.set 22
    local.get 22
    global.set $__stack_pointer
    return)
  (func $ecall_allocate_buffers (type 6) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i64 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 0
    i32.const 16
    local.set 1
    local.get 0
    local.get 1
    i32.sub
    local.set 2
    local.get 2
    global.set $__stack_pointer
    i32.const 1076
    local.set 3
    i32.const 0
    local.set 4
    local.get 3
    local.get 4
    call $printf
    drop
    call $init_buffers__
    i32.const 0
    local.set 5
    local.get 2
    local.get 5
    i32.store offset=12
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        i32.load offset=12
        local.set 6
        i32.const 16
        local.set 7
        local.get 6
        local.set 8
        local.get 7
        local.set 9
        local.get 8
        local.get 9
        i32.lt_s
        local.set 10
        i32.const 1
        local.set 11
        local.get 10
        local.get 11
        i32.and
        local.set 12
        local.get 12
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
        i32.load offset=12
        local.set 13
        i32.const 1152
        local.set 14
        i32.const 2
        local.set 15
        local.get 13
        local.get 15
        i32.shl
        local.set 16
        local.get 14
        local.get 16
        i32.add
        local.set 17
        local.get 17
        i32.load
        local.set 18
        local.get 2
        local.get 18
        i32.store offset=8
        local.get 2
        i32.load offset=12
        local.set 19
        local.get 19
        local.set 20
        local.get 20
        i64.extend_i32_s
        local.set 21
        local.get 2
        i32.load offset=8
        local.set 22
        local.get 22
        local.get 21
        i64.store
        local.get 2
        i32.load offset=12
        local.set 23
        i32.const 1
        local.set 24
        local.get 23
        local.get 24
        i32.add
        local.set 25
        local.get 2
        local.get 25
        i32.store offset=12
        br 0 (;@2;)
      end
    end
    call $free_buffers__
    i32.const 0
    local.set 26
    i32.const 16
    local.set 27
    local.get 2
    local.get 27
    i32.add
    local.set 28
    local.get 28
    global.set $__stack_pointer
    local.get 26
    return)
  (func $ecall_allocate_buffers_safe (type 6) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i64 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 0
    i32.const 16
    local.set 1
    local.get 0
    local.get 1
    i32.sub
    local.set 2
    local.get 2
    global.set $__stack_pointer
    i32.const 1096
    local.set 3
    i32.const 0
    local.set 4
    local.get 3
    local.get 4
    call $printf
    drop
    call $init_buffers_safe__
    i32.const 0
    local.set 5
    local.get 2
    local.get 5
    i32.store offset=12
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        i32.load offset=12
        local.set 6
        i32.const 16
        local.set 7
        local.get 6
        local.set 8
        local.get 7
        local.set 9
        local.get 8
        local.get 9
        i32.lt_s
        local.set 10
        i32.const 1
        local.set 11
        local.get 10
        local.get 11
        i32.and
        local.set 12
        local.get 12
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
        i32.load offset=12
        local.set 13
        i32.const 1152
        local.set 14
        i32.const 2
        local.set 15
        local.get 13
        local.get 15
        i32.shl
        local.set 16
        local.get 14
        local.get 16
        i32.add
        local.set 17
        local.get 17
        i32.load
        local.set 18
        local.get 2
        local.get 18
        i32.store offset=8
        local.get 2
        i32.load offset=12
        local.set 19
        local.get 19
        local.set 20
        local.get 20
        i64.extend_i32_s
        local.set 21
        local.get 2
        i32.load offset=8
        local.set 22
        local.get 22
        local.get 21
        i64.store
        local.get 2
        i32.load offset=12
        local.set 23
        i32.const 1
        local.set 24
        local.get 23
        local.get 24
        i32.add
        local.set 25
        local.get 2
        local.get 25
        i32.store offset=12
        br 0 (;@2;)
      end
    end
    call $free_buffers__
    i32.const 0
    local.set 26
    i32.const 16
    local.set 27
    local.get 2
    local.get 27
    i32.add
    local.set 28
    local.get 28
    global.set $__stack_pointer
    local.get 26
    return)
  (func $loop_int_ (type 2) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 1
    i32.const 16
    local.set 2
    local.get 1
    local.get 2
    i32.sub
    local.set 3
    local.get 3
    local.get 0
    i32.store offset=12
    i32.const 0
    local.set 4
    local.get 3
    local.get 4
    i32.store offset=8
    i32.const 0
    local.set 5
    local.get 3
    local.get 5
    i32.store offset=4
    block  ;; label = @1
      loop  ;; label = @2
        local.get 3
        i32.load offset=4
        local.set 6
        local.get 3
        i32.load offset=12
        local.set 7
        local.get 6
        local.set 8
        local.get 7
        local.set 9
        local.get 8
        local.get 9
        i32.lt_s
        local.set 10
        i32.const 1
        local.set 11
        local.get 10
        local.get 11
        i32.and
        local.set 12
        local.get 12
        i32.eqz
        br_if 1 (;@1;)
        local.get 3
        i32.load offset=8
        local.set 13
        i32.const 1
        local.set 14
        local.get 13
        local.get 14
        i32.add
        local.set 15
        local.get 3
        local.get 15
        i32.store offset=8
        local.get 3
        i32.load offset=4
        local.set 16
        i32.const 1
        local.set 17
        local.get 16
        local.get 17
        i32.add
        local.set 18
        local.get 3
        local.get 18
        i32.store offset=4
        br 0 (;@2;)
      end
    end
    unreachable
    unreachable)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 66752))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1044))
  (global (;3;) i32 (i32.const 1152))
  (global (;4;) i32 (i32.const 1024))
  (global (;5;) i32 (i32.const 1216))
  (global (;6;) i32 (i32.const 1024))
  (global (;7;) i32 (i32.const 66752))
  (global (;8;) i32 (i32.const 0))
  (global (;9;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "sgx_ecall_allocate_buffers" (func $sgx_ecall_allocate_buffers))
  (export "ecall_allocate_buffers" (func $ecall_allocate_buffers))
  (export "sgx_ecall_allocate_buffers_safe" (func $sgx_ecall_allocate_buffers_safe))
  (export "ecall_allocate_buffers_safe" (func $ecall_allocate_buffers_safe))
  (export "ocall_print_string" (func $ocall_print_string))
  (export "ocall_enc_untrusted_allocate_buffers" (func $ocall_enc_untrusted_allocate_buffers))
  (export "ocall_untrusted_local_free" (func $ocall_untrusted_local_free))
  (export "g_ecall_table" (global 1))
  (export "g_dyn_entry_table" (global 2))
  (export "printf" (func $printf))
  (export "_Z26allocate_untrusted_buffersmm" (func $allocate_untrusted_buffers_unsigned_long__unsigned_long_))
  (export "_Z12init_buffersv" (func $init_buffers__))
  (export "buffer_pool_" (global 3))
  (export "_Z17init_buffers_safev" (func $init_buffers_safe__))
  (export "_Z12free_buffersv" (func $free_buffers__))
  (export "_Z4loopi" (func $loop_int_))
  (export "__dso_handle" (global 4))
  (export "__data_end" (global 5))
  (export "__global_base" (global 6))
  (export "__heap_base" (global 7))
  (export "__memory_base" (global 8))
  (export "__table_base" (global 9))
  (data $.rodata (i32.const 1024) "\02\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\00\00\00\00Enclave/Enclave.cpp\00Allocating Buffers\0a\00Allocating Safe Buffers\0a\00OCALL return error %s %d\0a\00"))
