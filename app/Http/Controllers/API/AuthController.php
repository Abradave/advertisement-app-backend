<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Http\Requests\LoginRequest;
use App\Http\Requests\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(RegisterRequest $request){
        //$user = User::create($request->all());
        //return $user;
        //ha a laravel nem végezné el a password hashelést automazikusan:
        $user = User::create([
            "name" => $request->name,
            "email" => $request->email,
            "password" => Hash::make($request->password),
        ]);
        return response()->json($user, 201);
    }

    public function login(LoginRequest $request){
        //megvizsgáljuk h az "email" megegyezik-e a megadott emaillel
        //first() az első elemet adja vissza míg a get() több elemet, ezért itt first() kell
        $user = User::where("email", $request->email)->first();

        if(!$user || !Hash::check($request->password, $user->password)){
            //401-es státusz = nincs autentikálva a felhasználó
            return response()->json(["message" => "Incorrect username or password"], 401);
        }

        $token = $user->createToken("AuthToken")->plainTextToken;
        return response()->json(["token" => $token] );
    }

    public function logout(Request $request){
        //Token által hitelesített felhasználó lekérdezése
        //1. megoldás
        //$user = $request->user();
        //2. megoldás
        //$user = auth()->user();
        //3. megoldás
        //$user = Auth::user();

        $user = auth()->user();
        //A következő sort be kell írni, hogy ne jelezze ki a hibaüzenetet az alatta lévő sorra:
        /** @disregard P1013 Undefined method */
        $currentToken = $user->currentAccessToken()->delete();
        return response()->noContent();
        //$allTokens = $user->tokens;
        //return $allTokens;
    }

    public function logoutEverywhere(){
        $user = auth()->user();
        //A következő sort be kell írni, hogy ne jelezze ki a hibaüzenetet az alatta lévő sorra:
         /** @disregard P1013 Undefined method */
        $user->tokens()->delete();
        return response()->noContent();
    }
}
