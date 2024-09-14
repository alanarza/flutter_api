<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Auth;
use Validator;

class AuthController extends Controller
{
    public function register(Request $request){

        $input = $request->all();

        $validator = Validator::make($input, [
            'username' => 'required',
            'email' => 'required|email|unique:users,email',
            'password' => 'required',
            'confirm_password' => 'required|same:password'
        ]);

        if($validator->fails()){
            return response()->json(["status" => false, "message" => $validator->errors()], 400);
        }

        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);

        $response = [
            'success' => true,
            'data' => $user,
            'message' => 'User registered successfully'
        ];

        return response()->json($response, 200);
    }

    public function login(Request $request){

        $credentials = ['email' => $request->email, 'password' => $request->password];

        if(Auth::attempt($credentials)){

            $user = User::find(Auth::user()->id);

            if (!$user->hasVerifiedEmail()) {
                Auth::logout();
                $response = [
                    'success' => false,
                    'message' => 'Please verify your email before logging in.'
                ];

                return response()->json($response);
            } else {
                $success['token'] = $user->createToken('appToken')->accessToken;
                $success['username'] = $user->username;
                $success['email'] = $user->email;
                $success['id'] = $user->id;

                $response = [
                    'success' => true,
                    'data' => $success,
                    'message' => 'User login successfully'
                ];

                return response()->json($response, 200);
            }
        } else {

            $response = [
                'success' => false,
                'message' => 'Unauthorized'
            ];

            return response()->json($response);
        }
    }

    //corregir logout
    public function logout(Request $request)
    {
        $user = $request->user();

        if ($user) {
            $user->tokens()->where('device', $request->device)->delete();
        }

        auth()->logout();

        $response = [
            'success' => true,
            'message' => 'User logged out successfully',
        ];

        return response()->json($response, 200);
    }
}
