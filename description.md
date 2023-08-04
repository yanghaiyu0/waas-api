# 文档变更记录

Changes log, dates are displayed in UTC, shows in a reverse order.

### v0.9.0
> 2023/08/04 by Sinohope

-  add sinohope WaaS Api Document

First version

# 术语定义
<!-- 
# Main Steps

## Initiate

![](./images/setup_cva_share.png)

![](./images/setup_seq.png)

## Deposit

![](./images/deposit.png)

## Settlement

![](./images/settlement.png)

## Withdrawal

![](./images/withdraw.png)

-->
# API签名认证

## 概述

Sinnohope 使用 ECDSA 签名进行验证，您在 Sinnohope 开通账户以后，可以在您本地生成公私钥对,参考该URL下Sinnohope提供的例程：https://github.com/sinohope/sinohope-java-api，如有任何疑问，也可以联系我们的工作人员协助您。 您可以通过 Sinnohope Web 管理界面录入您的公钥 API Key （可选择类型：查询；所有）。 API Secret 请您自己妥善保管，不要透露给任何人，避免资产损失！ Sinnohope 强烈建议您绑定您的IP地址白名单以及启用“API回调”中的提现确认。 Sinnohope 的 API 请求，除公开的 API 外都需要携带 API key 以及签名。

## HTTP_METHOD

GET, POST 需要大写 请注意: Sinohope POST接口仅支持JSON数据格式


## HTTP_REQUEST_PATH

请求URL的PATH部分， 例如https://api.develop.sinohope.com/v1/test/ 为 /v1/test/

## NONCE

访问 API 时的 UNIX EPOCH 时间戳 (精确到毫秒)

## PARAMS

如果是GET请求： https://api.develop.sinohope.com/v1/test?username=username&password=password 则先将 key 按照字母排序，然后进行 url 参数化，即： password=password username=username 因为 p 在字母表中的排序在 u 之前，所以 password 要放在 username 之前，然后使用 & 进行连接，即： password=password&username=username 

###  代码示例： 

```java
   TreeMap params = new TreeMap<>();
    params.put("username", "username");
    params.put("password", "password");
    private static String composeParams (TreeMap params){
      StringBuffer buffer = new StringBuffer();
      params.forEach((s, o) -> {
        try {
          buffer.append(s).append("=").append(URLEncoder.encode(String.valueOf(o), "UTF-8")).append("&");
        } catch (UnsupportedEncodingException e) {
          e.printStackTrace();
        }
      });
      if (sb.length() > 0) {
        buffer.deleteCharAt(sb.length() - 1);
      }
      return  buffer.toString();
     }
 
 ```

如果是POST请求：{
"username":"username", "password":"password"
} 则将body整体参数当做String字符串来处理。

 
签名前的准备数据如下： 使用您本地生成的私钥（privateKey），对数据使用私钥进行 ECDSA 签名，并对二进制结果进行 Hex 编码, 即生成了用于向 API 服务器进行验证的最终签名 （可参考 Sinohope 例程：https://github.com/sinohope/sinohope-java-api)


## HEADER

BIZ-API-KEY - BIZ-API-SIGNATURE - BIZ-API-NONCE 将 Api key, nonce和右边生成的 signature 按上面的名称放入Header中, 即可通过签名验证。 

BIZ-API-KEY为您本地生成的publicKey。 获取公私钥
### 代码示例 
```java
public void getPublicKeyAndPrivateKey () throws Exception {
    ECDSA ecdsa = new ECDSA(SECP256R1);
    KeyPair keyPair = ecdsa.generateKeyPair();
    String publicKey = Hex.toHexString(keyPair.getPublic().getEncoded());
    String privateKey = Hex.toHexString(keyPair.getPrivate().getEncoded());
    System.out.println("publicKey = " + publicKey);
    System.out.println("privateKey = " + privateKey);
}


 ```

组装待签名数据和签名代码示例

```java

    String[] msg = doGenerateSignMetaDataAsString(apiKey, path, params);
    public static String[] doGenerateSignMetaDataAsString (String publicKey, String path, String data){
        Map map=new HashMap<>(4);
        map.put(Constants.TIMESTAMP,String.valueOf(LocalDateTime.now().toInstant(ZoneOffset.of("+8")).toEpochMilli())); // System.out.println("BIZ-API-NONCE is -> " + map.get(Constants.TIMESTAMP)); map.put(Constants.PATH, path); map.put(Constants.VERSION, "1.0.0"); map.put(Constants.DATA, StringUtils.isNotBlank(data) ? data : ""); String signature = map.keySet().stream() .sorted(Comparator.naturalOrder()) .map(key -> String.join("", key, map.get(key))) .collect(Collectors.joining()).trim() .concat(publicKey); return new String[]{signature, map.get(Constants.TIMESTAMP)}; } String signature = signer.sign(msg[0], signer.parsePKCS8PrivateKey(privateKey)); 
    }

```
获得数据如下： msg[0]：组装待签名数据， 生成规则如下： 时间戳（TIMESTAMP）：访问 API 时的 UNIX EPOCH 时间戳 (精确到毫秒)。 请求路径（PATH）：请求URL的PATH部分， 例如https://api.develop.sinohope.com/v1/test/ 为 /v1/test/。 版本号（VERSION）：固定值1.0.0。 请求数据（DATA）：如果数据为空则传空串。 上面几项组装成key和value键值对，对key进行自然排序并转换成key和value相连接的String字符串并去除头尾空白符。 msg[1]：时间戳（BIZ-API-NONCE） signature：BIZ-API-SIGNATURE


## 完整示例

### GET请求
GET请求： 暂时无法在Lark文档外展示此内容 参数 暂时无法在Lark文档外展示此内容 待签名数据为： datapassword=password&username=usernamepath/v1/testtimestamp1690959799750version1.0.03056301006072a8648ce3d020106052b8104000a03420004d8caf9385ee3f28df77eab42a0da4b8dc9462a8ad39dbb224c2802cc377df9dc09ac23d04748b40c2897d91bbd7fe859476c6f6fe9b2aa82607e8a48f9b7ac0d

### POST请求
POST请求： 暂时无法在Lark文档外展示此内容 参数 { "username": "username", "password": "password" } 待签名数据为： data{"username":"username","password":"password"}path/v1/testtimestamp1690961714929version1.0.03056301006072a8648ce3d020106052b8104000a03420004d8caf9385ee3f28df77eab42a0da4b8dc9462a8ad39dbb224c2802cc377df9dc09ac23d04748b40c2897d91bbd7fe859476c6f6fe9b2aa82607e8a48f9b7ac0d




# 常见错误码定义

Commonly, for all APIs, the HTTP status codes should use those registered by IANA.
See: <https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml>

当Sinohope WaaS 服务发生错误的时候，会返回给客户端统一格式的数据


- `200`: Successful response. Refer to each API for the detailed response data.
- `400`: Return Bad Request.
- `401`: Unauthorized. Either API details are missing or invalid
- `403`: Forbidden - You do not have access to the requested resource.
- `415`: Unsupported media type. You need to use application/json.
- `500`: Exchange/SinoHope internal error.
