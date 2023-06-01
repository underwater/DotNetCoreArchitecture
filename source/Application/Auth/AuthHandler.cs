namespace Architecture.Application;

public sealed record AuthHandler : IHandler<AuthRequest, AuthResponse>
{
    private readonly IAuthRepository _authRepository;
    private readonly IHashService _hashService;
    private readonly IJwtService _jwtService;
    private readonly IResultService _resultService;

    public AuthHandler
    (
        IAuthRepository authRepository,
        IHashService hashService,
        IJwtService jwtService,
        IResultService resultService
    )
    {
        _authRepository = authRepository;
        _hashService = hashService;
        _jwtService = jwtService;
        _resultService = resultService;
    }

    public async Task<Result<AuthResponse>> HandleAsync(AuthRequest request)
    {
        var auth = await _authRepository.GetByLoginAsync(request.Login);

        if (auth is null) return _resultService.Error<AuthResponse>("AuthError");

        var result = _hashService.Validate(auth.Password, request.Password, auth.Salt.ToString());

        if (result.IsError) return _resultService.Error<AuthResponse>("AuthError");

        var token = _jwtService.Encode(auth.Id.ToString(), auth.Roles.ToArray());

        var response = new AuthResponse(token);

        return _resultService.Success(response);
    }
}
