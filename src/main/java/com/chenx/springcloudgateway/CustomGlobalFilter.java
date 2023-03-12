package com.chenx.springcloudgateway;

import cn.hutool.core.util.StrUtil;
import com.api.api_client_sdk.utils.SignUtils;
import lombok.extern.slf4j.Slf4j;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Slf4j
@Component
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    private static final List<String> IP_WHITE_LIST = Collections.singletonList("127.0.0.1");

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //1.用户发送请求到 API 网关
        //2.请求日志
        ServerHttpRequest request = exchange.getRequest();
        log.info("请求唯一标识:" + request.getId());
        log.info("请求路径:" + request.getPath().value());
        log.info("请求方法: " + request.getMethod());
        log.info("请求参数：" + request.getQueryParams());
        String sourceAddress = request.getRemoteAddress().getHostString();
        log.info("请求来源地址:" + sourceAddress);
        log.info("localAddress:" +request.getLocalAddress());
        log.info("cookie:" + request.getCookies());
        //3.(黑白名单)
        ServerHttpResponse response = exchange.getResponse();
        if (!IP_WHITE_LIST.contains(sourceAddress)) {
            handleNoAuth(response);
        }
        //4.用户鉴权 (判断 ak、sk 是否合法)
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String body = headers.getFirst("body");
        String timestamp = headers.getFirst("timestamp");
        String sign = headers.getFirst("sign");
//        String accessKey = new String(request.getHeader("accessKey").getBytes("ISO-8859-1"), StandardCharsets.UTF_8);
//        String nonce = request.getHeader("nonce");
//        String body = new String(request.getHeader("body").getBytes("ISO-8859-1"),StandardCharsets.UTF_8);
//        String timestamp = request.getHeader("timestamp");
//        String sign = request.getHeader("sign");


        // todo 实际需要去数据库中查是否分配给了用户
        if (StrUtil.isEmpty(accessKey) || !Objects.equals(accessKey, "asd")) {
            handleNoAuth(response);
        }
        if (StrUtil.isEmpty(nonce) || Long.parseLong(nonce) > 1000L) {
            handleNoAuth(response);
        }

        long currentTime = System.currentTimeMillis() / 1000;
        long FIVE_MINUTES = 60 * 5L;
        if ((currentTime - Long.parseLong(timestamp)) >= FIVE_MINUTES ) {
            handleNoAuth(response);
        }

        // todo 数据库查到secretKey
        String serverSign = SignUtils.genSign(body, "asdasdasd");

        if (!serverSign.equals(sign)) {
            handleNoAuth(response);
        }
        //5，请求的模拟接口是否存在?
        // todo 从库中校验接口是否存在，以及请求方法是否匹配（还可以校验参数） 可以通过原后端项目提供接口这里访问接口获取数据进行校验
        //6。请求转发，调用模拟接口
//        Mono<Void> filter = chain.filter(exchange);
        //7。响应日志
        return testResponseLog(exchange, chain);
    }

    public Mono<Void> testResponseLog(ServerWebExchange exchange, GatewayFilterChain chain) {
        try {
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 缓存数据
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();

            HttpStatus statusCode = originalResponse.getStatusCode();

            if(statusCode == HttpStatus.OK){
                // 装饰 增强能力
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {

                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 往返回值里写数据 拼接字符串
                            return super.writeWith(fluxBody.map(dataBuffer -> {
                                byte[] content = new byte[dataBuffer.readableByteCount()];
                                dataBuffer.read(content);
                                DataBufferUtils.release(dataBuffer);//释放掉内存
                                // 构建日志
                                StringBuilder sb2 = new StringBuilder(200);
                                sb2.append("<--- {} {} \n");
                                List<Object> rspArgs = new ArrayList<>();
                                rspArgs.add(originalResponse.getStatusCode());
                                //rspArgs.add(requestUrl);
                                String data = new String(content, StandardCharsets.UTF_8);//data
                                sb2.append(data);
                                log.info("相应结果:" + data);
                                //8.调用成功，接口调用次数 + 1
                                // todo invokeCount

                                log.info(sb2.toString(), rspArgs.toArray());//log.info("<-- {} {}\n", originalResponse.getStatusCode(), data);
                                return bufferFactory.wrap(content);
                            }));
                        } else {
                            //9.调用失败，返回一个规范的错误码
                            handleInvokeError(originalResponse);
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            return chain.filter(exchange);//降级处理返回数据
        }catch (Exception e){
            log.error("gateway log exception.\n" + e);
            return chain.filter(exchange);
        }
    }

    @Override
    public int getOrder() {
        return -1;
    }

    private Mono<Void> handleNoAuth(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    private Mono<Void> handleInvokeError(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }
}

