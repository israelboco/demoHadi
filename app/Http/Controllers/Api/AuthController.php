<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    /**
     * Login Admin
     * 
     * @unauthenticated
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'max:255']
        ]);

        $user = User::where('email', $request->email)->first();
        if(!$user){
            return response()->json([
                'status' => false,
                'message' => 'Email incorrects',
            ], 401);
        }
        $password_verify = Hash::check($request->password, $user->password);
        if(!$password_verify){
            return response()->json([
                'status' => false,
                'message' => 'Password incorrects',
            ], 401);
        }
        return response()->json([
            'status' => true,
            'code' => 200,
            'message' => 'L\'utilisateur s\'est connecté avec succès',
            'token' => $user->createToken("API TOKEN")->plainTextToken,
            'user' => $user,
        ]);
    }


    /**
     * Register
     * 
     *@unauthenticated
     
     * @return \Illuminate\Http\JsonResponse
     */

     public function register(Request $request)
     {
         $request->validate([

            'name' => ['required', 'string'],
            'email' => ['required', 'email', 'unique:users,email'],
            'telephone' => ['required', 'string'],
            'adresse' => ['required', 'string'],
            'name' => ['required', 'string'],
            'password' => ['required', 'min:8', 'max:255'],
         ]);
 
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'telephone' => $request->telephone,
            'adresse' => $request->adresse,
            'password' => Hash::make($request->password),
            'role' => 'client'
        ]);
 
 
        return response()->json([
            'status' => true,
            'code' => 200,
            'message' => 'L\'utilisateur a été créé avec succès',
            'token' => $user->createToken("API TOKEN")->plainTextToken,
            'user' => $user,
        ]);
    }

    /**
     * Logout
    * @param  mixed $request
    */
    public function logout(Request $request)
    {
        Auth::logout();
        
        return response()->json([
            'status' => true,
            'code' => 200,
            'message' => 'Logout', 
        ]);

    }


    /**
     * get User
    */
    public function getUser()
    {
        $user = Auth::user();

        return response()->json([
            'status' => true,
            'code' => 200,
            'message' => 'get User',
            'data' => $user,
        ]);

    }



}
