package io.apicurio.registry.auth;

import io.apicurio.registry.AbstractResourceTestBase;
import io.apicurio.registry.ccompat.rest.ContentTypes;
import io.apicurio.registry.utils.tests.ApicurioTestTags;
import io.apicurio.registry.utils.tests.BasicAuthWithStrimziUsersTestProfile;
import io.fabric8.kubernetes.api.model.NamespaceBuilder;
import io.fabric8.kubernetes.api.model.SecretBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.NonDeletingOperation;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.quarkus.test.kubernetes.client.WithKubernetesTestServer;
import io.strimzi.api.kafka.Crds;
import io.strimzi.api.kafka.model.user.KafkaUserAuthorizationSimpleBuilder;
import io.strimzi.api.kafka.model.user.KafkaUserBuilder;
import io.strimzi.api.kafka.model.user.KafkaUserScramSha512ClientAuthenticationBuilder;
import io.strimzi.api.kafka.model.user.acl.*;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;

@QuarkusTest
@WithKubernetesTestServer
@TestProfile(BasicAuthWithStrimziUsersTestProfile.class)
@Tag(ApicurioTestTags.SLOW)
class TopicAclBasedAccessControllerTest extends AbstractResourceTestBase {
    @Inject
    KubernetesClient client;

    @Inject
    AuthConfig authConfig;

    private static final String SCHEMA_BODY = """
        {
          "schema": "{\\"type\\":\\"record\\",\\"name\\":\\"test\\",\\"fields\\":[{\\"type\\":\\"string\\",\\"name\\":\\"field1\\"},{\\"type\\": \\"string\\",\\"name\\": \\"int3\\"}]}",
          "schemaType": "AVRO",
          "references": [
          ]
        }
        """;

    @Override
    protected void deleteGlobalRules(int expectedDefaultRulesCount) throws Exception {
        // Do nothing
    }

    private static final String USERNAME = "alice";
    private static final String PASSWORD = "hunter2";

    @BeforeEach
    public void setupKubernetesResources() {
        NamespaceBuilder namespaceBuilder = new NamespaceBuilder().withNewMetadata().withName(authConfig.strimziKubernetesNamespace).endMetadata();
        client.namespaces().resource(namespaceBuilder.build()).createOr(NonDeletingOperation::update);
        // Create secret for user alice
        SecretBuilder secretBuilder = new SecretBuilder()
            .withNewMetadata()
            .withName(USERNAME)
            .withNamespace(authConfig.strimziKubernetesNamespace)
            .withLabels(Map.of("strimzi.io/kind", "KafkaUser"))
            .endMetadata()
            .addToData("password", Base64.getEncoder().encodeToString(PASSWORD.getBytes(StandardCharsets.UTF_8)));
        client.secrets().inNamespace(authConfig.strimziKubernetesNamespace).resource(secretBuilder.build()).createOr(NonDeletingOperation::update);
        // Create KafkaUser for user alice and allow them to read/write to "topic1", "topic2", and "my-topic"
        // then also deny them read/write access to everything prefixed with "topic"
        Crds.kafkaUserOperation(client)
            .inNamespace(authConfig.strimziKubernetesNamespace)
            .createOrReplace(new KafkaUserBuilder()
                .withNewMetadata()
                .withName(USERNAME)
                .endMetadata()
                .withNewSpec()
                .withAuthentication(new KafkaUserScramSha512ClientAuthenticationBuilder().build())
                .withAuthorization(new KafkaUserAuthorizationSimpleBuilder()
                    .withAcls(List.of(
                        new AclRuleBuilder()
                            .withResource(new AclRuleTopicResourceBuilder()
                                .withPatternType(AclResourcePatternType.LITERAL)
                                .withName("topic1")
                                .build())
                            .withOperations(List.of(AclOperation.READ, AclOperation.WRITE))
                            .withType(AclRuleType.ALLOW)
                            .build(),
                        new AclRuleBuilder()
                            .withResource(new AclRuleTopicResourceBuilder()
                                .withPatternType(AclResourcePatternType.LITERAL)
                                .withName("topic2")
                                .build())
                            .withOperations(List.of(AclOperation.READ, AclOperation.WRITE))
                            .withType(AclRuleType.ALLOW)
                            .build(),
                        new AclRuleBuilder()
                            .withResource(new AclRuleTopicResourceBuilder()
                                .withPatternType(AclResourcePatternType.PREFIX)
                                .withName("topic")
                                .build())
                            .withOperations(List.of(AclOperation.ALL))
                            .withType(AclRuleType.DENY)
                            .build(),
                        new AclRuleBuilder()
                            .withResource(new AclRuleTopicResourceBuilder()
                                .withPatternType(AclResourcePatternType.PREFIX)
                                .withName("my-topic")
                                .build())
                            .withOperations(List.of(AclOperation.READ, AclOperation.WRITE))
                            .withType(AclRuleType.ALLOW)
                            .build()
                    ))
                    .build())
                .endSpec()
                .build());
    }

    @Test
    void testForbidden() {
        given()
            .when()
            .contentType(ContentTypes.COMPAT_SCHEMA_REGISTRY_STABLE_LATEST)
            .body(SCHEMA_BODY)
            .with().auth().basic(USERNAME, PASSWORD)
            .post("/ccompat/v7/subjects/{subject}/versions", "topic1-value")
            .then()
            .statusCode(403);
        given()
            .when()
            .contentType(ContentTypes.COMPAT_SCHEMA_REGISTRY_STABLE_LATEST)
            .body(SCHEMA_BODY)
            .with().auth().basic(USERNAME, PASSWORD)
            .post("/ccompat/v7/subjects/{subject}/versions", "topic2-key")
            .then()
            .statusCode(403);
        given()
            .when()
            .contentType(ContentTypes.COMPAT_SCHEMA_REGISTRY_STABLE_LATEST)
            .body(SCHEMA_BODY)
            .with().auth().basic(USERNAME, PASSWORD)
            .post("/ccompat/v7/subjects/{subject}/versions", "asdf")
            .then()
            .statusCode(403);
    }

    @Test
    void testAuthorized() {
        given()
            .when()
            .contentType(ContentTypes.COMPAT_SCHEMA_REGISTRY_STABLE_LATEST)
            .body(SCHEMA_BODY)
            .with().auth().basic(USERNAME, PASSWORD)
            .post("/ccompat/v7/subjects/{subject}/versions", "my-topic-value")
            .then()
            .statusCode(200);
        given()
            .when()
            .contentType(ContentTypes.COMPAT_SCHEMA_REGISTRY_STABLE_LATEST)
            .body(SCHEMA_BODY)
            .with().auth().basic(USERNAME, PASSWORD)
            .post("/ccompat/v7/subjects/{subject}/versions", "my-topic-key")
            .then()
            .statusCode(200);
    }
}