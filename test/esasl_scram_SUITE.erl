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

-module(esasl_scram_SUITE).

-compile(export_all).
-compile(nowarn_export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(esasl),
    Config.

end_per_suite(_Config) ->
    application:stop(esasl).

all() -> [t_scram].

t_scram(_) ->
    Username = <<"admin">>,
    Password = <<"public">>,
    IterationCount = 4096,
    Algorithm = sha256,

    {StoredKey, ServerKey, Salt} = esasl_scram:generate_authentication_info(Password, #{algorithm => Algorithm, iteration_count => IterationCount}),
    RetrieveFun = fun(_) ->
                      {ok, #{stored_key => StoredKey,
                             server_key => ServerKey,
                             salt => Salt}}
                  end,

    ClientFirstMessage = esasl_scram:client_first_message(Username),

    {continue, ServerFirstMessage, ServerCache} =
        esasl_scram:check_client_first_message(
            ClientFirstMessage, 
            #{iteration_count => IterationCount,
              retrieve => RetrieveFun}
        ),

    {continue, ClientFinalMessage, ClientCache} =
        esasl_scram:check_server_first_message(
            ServerFirstMessage,
            #{client_first_message => ClientFirstMessage,
              password => Password,
              algorithm => Algorithm}
        ),

    {ok, ServerFinalMessage} =
        esasl_scram:check_client_final_message(
            ClientFinalMessage, ServerCache#{algorithm => Algorithm}
        ),

    ok = esasl_scram:check_server_final_message(
        ServerFinalMessage, ClientCache#{algorithm => Algorithm}
    ).