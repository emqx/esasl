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
    application:ensure_all_started(esasl),
    Config.

end_per_suite(_Config) ->
    application:stop(esasl).

all() -> [t_scram].

t_scram(_) ->
    Method = <<"SCRAM-SHA-1">>,
    Username = <<"test">>,
    Password = <<"public">>,
    Salt = <<"emqx">>,
    IterationCount = 4096,

    Context0 = esasl_app:init(Method, #{username => Username,
                                       password => Password,
                                       salt => Salt,
                                       iteration_count => IterationCount}),
    ClientFirst = esasl_app:apply(Method, Context0),
    {continue, ServerFirst, Context1} = esasl_app:check(Method, ClientFirst, Context0),
    {continue, ClientFinal, Context2} = esasl_app:check(Method, ServerFirst, maps:merge(Context0, #{client_first => ClientFirst})),
    {ok, ServerFinal, _} = esasl_app:check(Method, ClientFinal, Context1),
    {ok, <<>>, _} = esasl_app:check(Method, ServerFinal, Context2).
