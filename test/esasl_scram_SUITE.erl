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
    %% Port program dir
    BinDir = filename:join([code:lib_dir(esasl),
                            "test/bin/",
                            hd(string:tokens(erlang:system_info(system_architecture), "-"))]),
    [{bin_dir, BinDir} | Config].

end_per_suite(_Config) ->
    application:stop(esasl).

all() -> [t_scram, t_interop].

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

    ct:pal("ClientFirst: ~p", [ClientFirstMessage]),

    {continue, ServerFirstMessage, ServerCache} =
        esasl_scram:check_client_first_message(
            ClientFirstMessage, 
            #{iteration_count => IterationCount,
              retrieve => RetrieveFun}
        ),

    ct:pal("ServerFirst: ~p~nStates:~p", [ServerFirstMessage, ServerCache]),
    {continue, ClientFinalMessage, ClientCache} =
        esasl_scram:check_server_first_message(
            ServerFirstMessage,
            #{client_first_message => ClientFirstMessage,
              password => Password,
              algorithm => Algorithm}
        ),

    ct:pal("ClientFinal: ~p~n:State~p", [ClientFinalMessage, ClientCache]),
    {ok, ServerFinalMessage} =
        esasl_scram:check_client_final_message(
            ClientFinalMessage, ServerCache#{algorithm => Algorithm}
        ),

    ct:pal("ServerFinal: ~p", [ServerFinalMessage]),
    ok = esasl_scram:check_server_final_message(
        ServerFinalMessage, ClientCache#{algorithm => Algorithm}
    ).

t_interop(Config) ->
    process_flag(trap_exit, true),
    PortProgram = ?config(bin_dir, Config) ++ "/scram_cli",
    Username = <<"user">>,
    Password = <<"123456">>,
    Algorithm = sha256,
    IterationCount = 4096,
    PortOpenArgs = [Username, Password, atom_to_binary(Algorithm)],

    {StoredKey, ServerKey, Salt} = esasl_scram:generate_authentication_info(Password, #{algorithm => Algorithm, iteration_count => IterationCount}),

    RetrieveFun = fun(_) ->
                      {ok, #{stored_key => StoredKey,
                             server_key => ServerKey,
                             salt => Salt}}
                  end,

    Port = open_port({spawn_executable, PortProgram}, [{line, 1024},
                                                       {args, PortOpenArgs},
                                                       use_stdio,
                                                       binary
                                                      ]),

    ClientFirstMessage = recv_from_port(Port),

    {continue, ServerFirstMessage, ServerCache} =
        esasl_scram:check_client_first_message(
          ClientFirstMessage,
          #{iteration_count => IterationCount,
            retrieve => RetrieveFun}),

    send_to_port(Port, ServerFirstMessage),
    ClientFinalMessage = recv_from_port(Port),
    {ok, ServerFinalMessage} =
        esasl_scram:check_client_final_message(
          ClientFinalMessage, ServerCache#{algorithm => Algorithm}
         ),
    send_to_port(Port, ServerFinalMessage),
    ?assertEqual(<<"AUTH OK">>, recv_from_port(Port)).

%% helpers
recv_from_port(Port) ->
    receive
        {Port, {data, {eol, Data}}} ->
            ct:pal("recv from Port: ~p", [Data]),
            Data;
        {Port, Unsupp} ->
            ct:fail("recv from Port but unsupported data: ~p", [Unsupp])
    after 10000 ->
            ct:fail("failed to recv from Port")
    end.

send_to_port(Port, RawData) when is_binary(RawData) ->
    ct:pal("sent to Port: ~p", [RawData]),
    Port ! {self(), {command, <<RawData/binary, "\n">>}}.
