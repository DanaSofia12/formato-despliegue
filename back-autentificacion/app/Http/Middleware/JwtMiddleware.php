<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Http\Response as HttpResponse;
use Symfony\Component\HttpFoundation\Response;

class JwtMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */

    public function handle(Request $request, Closure $next): Response
    {
        $token = $request->header('authorization');
        if(!$token){
            return response()->json(['error'=> 'token not previded'], HttpResponse::HTTP_BAD_REQUEST);
        }

        try{
            $token = str_replace('Bearer ', ''. $token);
            $decoded = JWT::decode($token, new Key(env('JWT_SECRET'),'HS256'));
            return $next($request);      
        }catch(ExpiredException $e){
            return response()->json(['error' => 'Token ha expirado'], HttpResponse::HTTP_UNAUTHORIZED);
        }catch(Exception $e){
            return response()->json(['error' => 'Token Invalido: ',$e->getMessage()], HttpResponse::HTTP_UNAUTHORIZED);
        }

       
    }
}
