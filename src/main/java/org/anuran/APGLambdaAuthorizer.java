package org.anuran;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayCustomAuthorizerEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerificationException;
import com.okta.jwt.JwtVerifiers;
import jakarta.inject.Named;
import org.anuran.org.anuran.model.AuthPolicy;
import org.anuran.org.anuran.model.AuthResonse;
import org.anuran.org.anuran.model.TokenAuthorizerContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Named("authorizer")
public class APGLambdaAuthorizer implements RequestHandler<TokenAuthorizerContext, AuthPolicy> {

    Logger logger = LoggerFactory.getLogger(APGLambdaAuthorizer.class);
    @Override
    public AuthPolicy handleRequest(TokenAuthorizerContext input, Context context) {

        String token = input.getAuthorizationToken().split(" ")[1];
        logger.info("Authorization Token received from API Gateway is {}", token);

        // validate the incoming token
        // and produce the principal user identifier associated with the token
        // this could be accomplished in a number of ways:
        // 1. Call out to OAuth provider
        // 2. Decode a JWT token in-line
        // 3. Lookup in a self-managed DB

        AccessTokenVerifier jwtVerifier = JwtVerifiers.accessTokenVerifierBuilder()
                .setIssuer("https://dev-76789052.okta.com/oauth2/auselj90dmLJUlb5z5d7")
                .setAudience("api://jwtauthtest")   // defaults to 'api://default'
                .setConnectionTimeout(Duration.ofSeconds(15))    // defaults to 1s
//                .setRetryMaxAttempts(2)                     // defaults to 2
//                .setRetryMaxElapsed(Duration.ofSeconds(10))     // defaults to 10s
//                .setPreloadSigningKeys(true)                // defaults to false
                .build();


        ObjectMapper mapper = new ObjectMapper();
        try {
            logger.info("AccessTokenVerifier instantiated = {}", mapper.writeValueAsString(jwtVerifier.toString()));
        } catch (JsonProcessingException e) {
            e.printStackTrace();
//            throw new RuntimeException(e);
        }

        // if the client token is not recognized or invalid
        // you can send a 401 Unauthorized response to the client by failing like so:
        // throw new RuntimeException("Unauthorized");

        String principalId = "";
        boolean isAdmin = false;
        try {
            Jwt jwt = jwtVerifier.decode(token);
            principalId = (String) jwt.getClaims().get("sub");     //"anuran.datta@hotmail.com";
            List groupsClaim = (ArrayList<String>) jwt.getClaims().get("Groups");
            isAdmin = groupsClaim.contains("SuperUser");
        } catch (JwtVerificationException e) {
            e.printStackTrace();
            throw new RuntimeException("Unauthorized");
        }
        logger.info("Is Admin = {}", isAdmin);

        // if the token is valid, a policy should be generated which will allow or deny access to the client

        // if access is denied, the client will receive a 403 Access Denied response
        // if access is allowed, API Gateway will proceed with the back-end integration configured on the method that was called

        String methodArn = input.getMethodArn();
        logger.info("MethodArn received from API Gateway is {}", methodArn);
        String[] arnPartials = methodArn.split(":");
        String region = arnPartials[3];
        String awsAccountId = arnPartials[4];
        String[] apiGatewayArnPartials = arnPartials[5].split("/");
        String restApiId = apiGatewayArnPartials[0];
        String stage = apiGatewayArnPartials[1];
        String httpMethod = apiGatewayArnPartials[2];
        String resource = ""; // root resource
        if (apiGatewayArnPartials.length >= 4) {
            resource = apiGatewayArnPartials[3] + "/*";
        }

        // this function must generate a policy that is associated with the recognized principal user identifier.
        // depending on your use case, you might store policies in a DB, or generate them on the fly

        AuthPolicy ap = null;


        if ((resource.startsWith("blog/api/posts") || resource.startsWith("blog/api/tags"))
                && !AuthPolicy.HttpMethod.GET.toString().equalsIgnoreCase(httpMethod)
                && !isAdmin) {

            // the example policy below denies access to one resource in the RestApi
            ap = new AuthPolicy(principalId, AuthPolicy.PolicyDocument.getDenyOnePolicy(region, awsAccountId, restApiId, stage,
                    AuthPolicy.HttpMethod.valueOf(httpMethod.toUpperCase()), resource));
        } else {

            // keep in mind, the policy is cached for 5 minutes by default (TTL is configurable in the authorizer)
            // and will apply to subsequent calls to any method/resource in the RestApi
            // made with the same token

            // the example policy below allows access to all resources in the RestApi

            ap = new AuthPolicy(principalId, AuthPolicy.PolicyDocument.getAllowAllPolicy(region, awsAccountId, restApiId, stage));
        }

        try {
            logger.info("Auth policy generated :\n{}", mapper.writeValueAsString(ap));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return ap;
    }
}
/*public class APGProxyLambda implements RequestHandler<APIGatewayCustomAuthorizerEvent, AuthResonse> {

    Logger logger = LoggerFactory.getLogger(APGProxyLambda.class);

    ObjectMapper mapper = new ObjectMapper();

    @Override
    public AuthResonse handleRequest(APIGatewayCustomAuthorizerEvent event, Context context) {
//        APIGatewayProxyResponseEvent response = new APIGatewayProxyResponseEvent();

//        try {
            logger.info(String.valueOf(event));
            String token = event.getAuthorizationToken();
            logger.info(token);
//            String resp = mapper.writeValueAsString(new AuthResonse());
//            logger.info(resp);
//            response.setBody(resp);

//        } catch (JsonProcessingException e) {
//            e.printStackTrace();
//        }
//        response.setStatusCode(200);
//        return response;
       return new AuthResonse();
    }
}*/
