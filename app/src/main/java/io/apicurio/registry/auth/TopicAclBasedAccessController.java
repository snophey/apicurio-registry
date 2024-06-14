package io.apicurio.registry.auth;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.strimzi.api.kafka.Crds;
import io.strimzi.api.kafka.model.user.KafkaUser;
import io.strimzi.api.kafka.model.user.KafkaUserAuthorizationSimple;
import io.strimzi.api.kafka.model.user.KafkaUserSpec;
import io.strimzi.api.kafka.model.user.acl.*;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.interceptor.InvocationContext;
import org.slf4j.Logger;

import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class TopicAclBasedAccessController extends AbstractAccessController {
    @Inject
    AuthConfig authConfig;

    @Inject
    KubernetesClient client;

    @Inject
    Logger log;

    public TopicAclBasedAccessController() {
    }

    /**
     * @see io.apicurio.registry.auth.IAccessController#isAuthorized(jakarta.interceptor.InvocationContext)
     */
    @Override
    public boolean isAuthorized(InvocationContext context) {
        Authorized annotation = context.getMethod().getAnnotation(Authorized.class);
        AuthorizedLevel level = annotation.level();
        AuthorizedStyle style = annotation.style();

        // We follow the same permission model as that of Confluent's Topic ACL Authorizer
        // https://docs.confluent.io/platform/current/confluent-security-plugins/schema-registry/authorization/topicacl_authorizer.html
        var topicName = getTopicName(context);
        if (topicName == null) {
            // If the topic name cannot be extracted (because the operation is not related to a topic), then behave
            // as if the operation is authorized.
            return true;
        }

        return switch (level) {
            case Read -> canReadTopic(topicName);
            case Write -> canWriteTopic(topicName);
            default -> false;
        };
    }

    private String getTopicName(InvocationContext context) {
        // Extract the topic name from the method arguments
        Authorized annotation = context.getMethod().getAnnotation(Authorized.class);
        AuthorizedStyle style = annotation.style();

        String subjectName = null;
        if (style == AuthorizedStyle.GroupAndArtifact) {
            subjectName = getStringParam(context, 1);
        } else if (style == AuthorizedStyle.ArtifactOnly) {
            subjectName = getStringParam(context, 0);
        }
        // Assume that TopicNameStrategy is used (https://developer.confluent.io/courses/schema-registry/schema-subjects/#topicnamestrategy)
        // (Confluent's Schema Registry Topic ACL Authorizer makes the same assumption)
        return Optional.ofNullable(subjectName)
            .map(name -> name.replaceAll("(-key|-value)$", ""))
            .filter(name -> !name.isBlank())
            .orElse(null);
    }

    private boolean canReadTopic(String topicName) {
        return canAccessTopic(topicName, AclOperation.READ);
    }

    private boolean canWriteTopic(String topicName) {
        return canAccessTopic(topicName, AclOperation.WRITE);
    }

    private boolean canAccessTopic(String topicName, AclOperation operation) {
        // Check if the Strimzi user whose name is the same as the principal name has <operation> permission on the topic
        KafkaUser user = Crds.kafkaUserOperation(client)
            .inNamespace(authConfig.strimziKubernetesNamespace)
            .list()
            .getItems()
            .stream()
            .filter(u -> u.getMetadata().getName().equals(securityIdentity.getPrincipal().getName()))
            .findFirst()
            .orElse(null);
        // simple authorization type means that ACLs are managed by the Kafka Admin API
        KafkaUserAuthorizationSimple authorization = (KafkaUserAuthorizationSimple) Optional.ofNullable(user)
            .map(KafkaUser::getSpec)
            .map(KafkaUserSpec::getAuthorization)
            .filter(auth -> "simple".equals(auth.getType()))
            .orElse(null);
        if (authorization == null) {
            return false;
        }
        // if there is an ALLOW rule for the operation and no DENY rule, then the operation is allowed
        // if there is a DENY rule for the operation, then the operation is denied even if there is an ALLOW rule
        return aclRuleExistsForTopic(topicName, AclRuleType.ALLOW, operation, authorization.getAcls())
            && !aclRuleExistsForTopic(topicName, AclRuleType.DENY, operation, authorization.getAcls());
    }

    private boolean aclRuleExistsForTopic(String topicName, AclRuleType ruleType, AclOperation operation, List<AclRule> acls) {
        return acls.stream()
            .filter(acl -> acl.getResource().getType().equals("topic"))
            .filter(acl -> acl.getOperations().contains(operation) || acl.getOperations().contains(AclOperation.ALL))
            .filter(acl -> acl.getType() == ruleType)
            .anyMatch(acl -> {
                var resource = (AclRuleTopicResource) acl.getResource();
                var prefixMatch = resource.getPatternType() == AclResourcePatternType.PREFIX;
                return prefixMatch ? topicName.startsWith(resource.getName()) : topicName.equals(resource.getName());
            });
    }
}
