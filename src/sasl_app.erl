%%%-------------------------------------------------------------------
%% @doc sasl public API
%% @end
%%%-------------------------------------------------------------------

-module(sasl_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    sasl_sup:start_link(),
    sasl_scram:init().

stop(_State) ->
    ok.

%% internal functions
