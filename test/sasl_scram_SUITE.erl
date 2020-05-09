%%--------------------------------------------------------------------
%% Copyright (c) 2020 EMQ Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(sasl_scram_SUITE).

-compile(export_all).
-compile(nowarn_export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

init_per_suite(Config) ->
    application:ensure_all_started(sasl),
    ekka_mnesia:copy_schema(node()),
    sasl_scram:init(),
    Config.

end_per_suite(_Config) ->
    application:stop(sasl).

all() -> [t_crud, t_scram].

t_crud(_) ->
    Username = <<"test">>,
    Password = <<"public">>,
    Salt = <<"emqx">>,
    IterationCount = 4096,
    EncodedSalt = base64:encode(Salt),
    SaltedPassword = sasl_scram:pbkdf2_sha_1(Password, Salt, IterationCount),
    ClientKey = sasl_scram:client_key(SaltedPassword),
    ServerKey = base64:encode(sasl_scram:server_key(SaltedPassword)),
    StoredKey = base64:encode(crypto:hash(sha, ClientKey)),

    {error, not_found} = sasl_scram:lookup(Username),
    ok = sasl_scram:add(Username, Password, Salt),
    {error, already_existed} = sasl_scram:add(Username, Password, Salt),

    {ok, #{username := Username,
           stored_key := StoredKey,
           server_key := ServerKey,
           salt := EncodedSalt,
           iteration_count := IterationCount}} = sasl_scram:lookup(Username),

    NewSalt = <<"new salt">>,
    NewEncodedSalt = base64:encode(NewSalt),
    sasl_scram:update(Username, Password, NewSalt),
    {ok, #{username := Username,
           salt := NewEncodedSalt}} = sasl_scram:lookup(Username),
    sasl_scram:delete(Username),
    {error, not_found} = sasl_scram:lookup(Username).

t_scram(_) ->
    Username = <<"test">>,
    Password = <<"public">>,
    Salt = <<"emqx">>,
    ok = sasl_scram:add(Username, Password, Salt),
    ClientFirst = sasl_scram:make_client_first(Username),

    {continue, ServerFirst, Cache} = sasl_scram:check(ClientFirst, #{}),

    {continue, ClientFinal, ClientCache} = sasl_scram:check(ServerFirst, #{password => Password, client_first => ClientFirst}),

    {ok, ServerFinal, #{}} = sasl_scram:check(ClientFinal, Cache),

    {ok,<<>>,#{}} = sasl_scram:check(ServerFinal, ClientCache).
