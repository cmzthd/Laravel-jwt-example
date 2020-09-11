### Laravel 5 中使用 JWT（Json Web Token） 实现基于API的用户认证

在JavaScript前端技术大行其道的今天，我们通常只需在后台构建API提供给前端调用，并且后端仅仅设计为给前端移动App调用。用户认证是Web应用的重要组成部分，基于API的用户认证有两个最佳解决方案 —— OAuth 2.0 和 JWT（JSON Web Token）。

#### JWT定义及其组成
JWT（JSON Web Token）是一个非常轻巧的规范。这个规范允许我们使用JWT在用户和服务器之间传递安全可靠的信息。

一个JWT实际上就是一个字符串，它由三部分组成，头部、载荷与签名。

#### 载荷（Payload）
我们先将用户认证的操作描述成一个JSON对象。其中添加了一些其他的信息，帮助今后收到这个JWT的服务器理解这个JWT。
```
{
    "sub": "1",
    "iss": "http://localhost:8000/auth/login",
    "iat": 1451888119,
    "exp": 1454516119,
    "nbf": 1451888119,
    "jti": "37c107e4609ddbcc9c096ea5ee76c667"
}
```

这里面的前6个字段都是由JWT的标准所定义的。
+ sub: 该JWT所面向的用户
+ iss: 该JWT的签发者
+ iat(issued at): 在什么时候签发的token 
+ exp(expires): token什么时候过期
+ nbf(not before)：token在此时间之前不能被接收处理
+ jti：JWT ID为web token提供唯一标识

[标准]: https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32 "创作你的创作"
这些定义都可以在[标准]中找到。

将上面的JSON对象进行base64编码可以得到下面的字符串：

```
eyJzdWIiOiIxIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWx
ob3N0OjgwMDFcL2F1dGhcL2xvZ2luIiwiaWF0IjoxNDUxODg4MTE5LCJleHAiOjE0NTQ1MTYxMTksIm5iZiI6MTQ1MTg4OD
ExOSwianRpIjoiMzdjMTA3ZTQ2MDlkZGJjYzljMDk2ZWE1ZWU3NmM2NjcifQ
```
这个字符串我们将它称作JWT的Payload（载荷）。

如果你使用Node.js，可以用Node.js的包base64url来得到这个字符串：

```
var base64url = require('base64url')
var header = {
    "from_user": "B",
    "target_user": "A"
}
console.log(base64url(JSON.stringify(header)))
```

> 注：Base64是一种编码，也就是说，它是可以被翻译回原来的样子来的。它并不是一种加密过程。

### 头部（Header）
JWT还需要一个头部，头部用于描述关于该JWT的最基本的信息，例如其类型以及签名所用的算法等。这也可以被表示成一个JSON对象：
```
{
  "typ": "JWT",
  "alg": "HS256"
}
```

在这里，我们说明了这是一个JWT，并且我们所用的签名算法（后面会提到）是HS256算法。

对它也要进行Base64编码，之后的字符串就成了JWT的Header（头部）：

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9
```

### 签名（签名）
将上面的两个编码后的字符串都用句号.连接在一起（头部在前），就形成了：

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWx
ob3N0OjgwMDFcL2F1dGhcL2xvZ2luIiwiaWF0IjoxNDUxODg4MTE5LCJleHAiOjE0NTQ1MTYxMTksIm5iZiI6MTQ1MTg4OD
ExOSwianRpIjoiMzdjMTA3ZTQ2MDlkZGJjYzljMDk2ZWE1ZWU3NmM2NjcifQ
```
最后，我们将上面拼接完的字符串用HS256算法进行加密。在加密的时候，我们还需要提供一个密钥（secret）:

```
HMACSHA256(
    base64UrlEncode(header) + "." +
    base64UrlEncode(payload),
    secret
)
```

这样就可以得到我们加密后的内容：

```
wyoQ95RjAyQ2FF3aj8EvCSaUmeP0KUqcCJDENNfnaT4
```
这一部分又叫做签名。

最后将这一部分签名也拼接在被签名的字符串后面，我们就得到了完整的JWT：

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIiwiaXNzIjoiaHR0cDpcL1wvbG9jYWx
ob3N0OjgwMDFcL2F1dGhcL2xvZ2luIiwiaWF0IjoxNDUxODg4MTE5LCJleHAiOjE0NTQ1MTYxMTksIm5iZiI6MTQ1MTg4OD
ExOSwianRpIjoiMzdjMTA3ZTQ2MDlkZGJjYzljMDk2ZWE1ZWU3NmM2NjcifQ.wyoQ95RjAyQ2FF3aj8EvCSaUmeP0KUqcCJDENNfnaT4
```

### 通过JWT 进行认证
JWT 是一个令牌（Token），客户端得到这个服务器返回的令牌后，可以将其存储到 Cookie 或 localStorage 中，此后，每次与服务器通信都要带上这个令牌，你可以把它放到 Cookie 中自动发送，但这样做不能跨域，所以更好的做法是将其放到 HTTP 请求头 Authorization 字段里面：
```
Authorization: Bearer <token>
```

###集成JWT到Laravel 5
####安装
我们使用Composer安装jwt扩展包：

```
composer require tymon/jwt-auth
```

###配置
安装完成后，需要在config/app.php中注册相应的服务提供者（Laravel 5.4 及以下版本，Laravel 5.5 + 版本会自动发现该扩展包）：
```
Tymon\JWTAuth\Providers\JWTAuthServiceProvider::class
```

然后发布相应配置文件：
```
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\JWTAuthServiceProvider"
```

生成jwt token加密秘钥
```
php artisan jwt:secret

```

>注：如果你是用的 tymon/jwt-auth 是 0.5.* 版本的，请使用php artisan jwt:generate命令生成密钥。

如果你想要将其添加到.env文件中，在.env中创建JWT_SECRET字段并再次执行生成密钥的命令。

在config/jwt.php中，你可以配置以下选项：

+ ttl：token有效期（分钟）
+ refresh_ttl：刷新token时间（分钟）
+ algo：token签名算法
+ user：指向User模型的命名空间路径
+ identifier：用于从token的sub中获取用户
+ require_claims：必须出现在token的payload中的选项，否则会抛出TokenInvalidException异常
+ blacklist_enabled：如果该选项被设置为false，那么我们将不能废止token，即使我们刷新了token，前一个token仍然有效
+ providers：完成各种任务的具体实现，如果需要的话你可以重写他们
+ User —— providers.user：基于sub获取用户的实现
+ JWT —— providers.jwt：加密/解密token
+ Authentication —— providers.auth：通过证书/ID获取认证用户
+ Storage —— providers.storage：存储token直到它们失效

###创建Admin模型
在开始之前，还需要让 Admin 模型类实现 JWTSubject 接口：

```
<?php


namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Tymon\JWTAuth\Contracts\JWTSubject;

/**
 * Class Admin
 *
 * @property int $id
 * @property string $account_num
 * @property string $password
 * @property int $status
 * @property int $create_time
 * @property int $update_time
 *
 * @package App\Models
 */
class Admin extends Authenticatable implements JWTSubject
{
	protected $connection = 'mysql';
	protected $table = 'admin';
	public $timestamps = false;

	protected $casts = [
		'status' => 'int',
		'create_time' => 'int',
		'update_time' => 'int'
	];

	protected $hidden = [
		'password'
	];

	protected $fillable = [
		'account_num',
		'password',
		'status',
		'create_time',
		'update_time'
	];

	/**
	 * Get the identifier that will be stored in the subject claim of the JWT.
	 *
	 * @return mixed
	 */
	public function getJWTIdentifier()
	{
		return $this->getKey();
	}

	/**
	 * Return a key value array, containing any custom claims to be added to the JWT.
	 *
	 * @return array
	 */
	public function getJWTCustomClaims()
	{
		return [];
	}
}

```



修改配置文件config/auth.php 文件
```
    'guards' => [
        ```
        // 添加新的验证方法
		'admin'=>[ // 当前名称可自定义
			'driver'=>'jwt',    // 验证引擎
			'provider'=>'user' // 对应的用户数据库
		]
    ],

```
```
    'providers' => [
        // 可新建或修改验证用户表
        'admin' => [
            'driver' => 'eloquent',
            'model' => App\Models\Admin::class,//对应第二步创建的
        ]
    ],
```

创建用户token最常用的方式就是通过登录实现用户认证，如果成功则返回相应用户的token。这里假设我们有一个AuthenticateController：

```

use App\Models\Admin;

class AuthenticateController extends Controller
{
    /**
     * 登录方法(可封装)
     */
    public function login() {
            $accountNum = request('account_num');
            $password = request('password');
            $result      = [];
            $credentials = ['account_num' => $accountNum, "password" => $password];
            $token       = auth('admin')->attempt($credentials);
    
            if ($token) {
                $result['token'] = $token;
            }
    
            return $result;
    }
    
    /**
     * 退出登录(可封装)
     */
    public function logout() {
            return auth('admin')->logout();
    }
    
    /**
     * 注册(可封装)
     */
    public function register() {
                $accountNum = request('account_num');
                $password = request('password');
                $data   = [
        			"account_num" => $accountNum,
        			"password"    => bcrypt($password),
        			"create_time" => time()
        		];
        		$result = Admin::create($data) ? true : false;
    }
    
    /**
     * 获取用户信息(可封装)
     * token 的参数名为 token
     */
    public function getUserInfo() {
        return auth('admin')->user();
    }
    
    /**
     * 验证密码(可封装)
     * token 的参数名为 token
     */
    public function checkPassword() {
        $data = \request()->only(['account_no','password']);
        return auth('admin')->validate($data)
    }
    
    /**
     * 验证token值(可封装)
     * token 的参数名为 token
     */
    public function check() {
        return auth('admin')->check()
    }
}
```
