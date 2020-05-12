%%%-------------------------------------------------------------------
%% @doc sasl public API
%% @end
%%%-------------------------------------------------------------------

-module(sasl_app).

-export([ init/2
        , apply/2
        , check/3
        , supported/0]).

init(<<"SCRAM-SHA-1">>, #{username := Username,
                          password := Password,
                          salt := Salt,
                          iteration_count := IterationCount}) ->
    sasl_scram:init(Username, Password, Salt, IterationCount);

init(_Method, _Context) ->
    {error, init_failed}.

apply(<<"SCRAM-SHA-1">>, _Context = #{username := Username}) ->
    sasl_scram:make_client_first(Username);

apply(_Method, _Context) ->
    {error, unsupported_methods}.

check(<<"SCRAM-SHA-1">>, Data, Context) ->
    safe_execute(fun sasl_scram:check/2, [Data, Context]);

check(_Method, _Data, _Context) ->
    {error, authentication_failed}.

supported() ->
    [<<"SCRAM-SHA-1">>].

%%--------------------------------------------------------------------
%% help functions
%%--------------------------------------------------------------------

safe_execute(Fun, Args) ->
    try
        execute(Fun, Args)
    catch
        _:Reason:_Stacktrace ->
            {error, Reason}
    end.

execute(Fun, Args) when is_function(Fun) ->
    erlang:apply(Fun, Args).