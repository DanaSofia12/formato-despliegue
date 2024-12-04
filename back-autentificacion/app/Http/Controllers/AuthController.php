<?php

namespace App\Http\Controllers;


use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register']]);
    }

    /**
     * Get a JWT token via given credentials.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if ($token = $this->guard()->attempt($credentials)) {
            return $this->respondWithToken($token);
        }

        return response()->json(['error' => 'Unauthorized'], Response::HTTP_UNAUTHORIZED);
    }

    public function register(Request $request)
{
    $validar = Validator::make($request->all(), [
        'name' => 'required|string|max:255',
        'username' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'password' => 'required|string|min:6',
        'position_name' => 'required|string', 
        'jefe_id' => 'nullable|exists:users,id', 
    ]);

    if ($validar->fails()) {
        return response()->json(['error' => $validar->errors()], Response::HTTP_BAD_REQUEST);
    }

    try {
        // Buscar o crear la posición
        $position = \App\Models\Position::firstOrCreate(
            ['name' => $request->input('position_name')],
            ['priority' => 1] // Asigna un valor predeterminado si es nuevo
        );

        // Obtener el jefe si se proporciona
        $jefe_id = $request->input('jefe_id'); // El jefe_id puede ser nulo
        $jefe = $jefe_id ? \App\Models\User::find($jefe_id) : null;

        // Crear el usuario con la posición asociada y jefe (si se proporciona)
        $user = User::create([
            'name' => $request->input('name'),
            'username' => $request->input('username'),
            'email' => $request->input('email'),
            'password' => Hash::make($request->input('password')),
            'position' => $position->id,
            'jefe_id' => $jefe ? $jefe->id : null, // Asigna el jefe solo si existe, de lo contrario asigna null
        ]);

        return response()->json([
            'message' => 'Guardado con éxito',
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'username' => $user->username,
                'email' => $user->email,
                'position' => $position->name,
                'jefe_id' => $user->jefe_id, // Incluye el jefe_id en la respuesta
            ],
        ], Response::HTTP_CREATED);
    } catch (\Exception $e) {
        return response()->json(['error' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
    }
}

    

    /**
     * Get the authenticated User
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json($this->guard()->user());
    }

    /**
     * Log the user out (Invalidate the token)
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        $this->guard()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken($this->guard()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => $this->guard()->factory()->getTTL() * 60
        ],);
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\Guard
     */
    public function guard()
    {
        return Auth::guard();
    }
}