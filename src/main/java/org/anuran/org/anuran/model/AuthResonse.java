package org.anuran.org.anuran.model;

import com.amazonaws.services.lambda.runtime.events.AppSyncLambdaAuthorizerResponse;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponse;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
class Statement {
    private String Action;
    private String Effect;
    private String Resource;
}

@Data
@NoArgsConstructor
class PolicyDocument {
    private String Version;
    private List<Statement> Statement;
}

@Data
public class AuthResonse {
    private String principalId;
    private PolicyDocument policyDocument;

    public AuthResonse() {
        principalId = "user"; // The principal user identification associated with the token sent by the client.
        policyDocument = new PolicyDocument();
        policyDocument.setVersion("2012-10-17");
        policyDocument.setStatement(new ArrayList<>());
        policyDocument.getStatement().add(new Statement());
        policyDocument.getStatement().get(0).setAction("execute-api:Invoke");
        policyDocument.getStatement().get(0).setEffect("Allow");
        policyDocument.getStatement().get(0).setResource("arn:aws:execute-api:us-east-1:161710045430:6oqs9mh93k/Prod/GET/");

    }

}
