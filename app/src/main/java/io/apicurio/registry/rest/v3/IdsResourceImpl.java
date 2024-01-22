package io.apicurio.registry.rest.v3;

import io.apicurio.common.apps.logging.Logged;
import io.apicurio.registry.auth.Authorized;
import io.apicurio.registry.auth.AuthorizedLevel;
import io.apicurio.registry.auth.AuthorizedStyle;
import io.apicurio.registry.content.ContentHandle;
import io.apicurio.registry.metrics.health.liveness.ResponseErrorLivenessCheck;
import io.apicurio.registry.metrics.health.readiness.ResponseTimeoutReadinessCheck;
import io.apicurio.registry.rest.HeadersHack;
import io.apicurio.registry.rest.v3.beans.ArtifactReference;
import io.apicurio.registry.rest.v3.beans.HandleReferencesType;
import io.apicurio.registry.rest.v3.shared.CommonResourceOperations;
import io.apicurio.registry.storage.dto.ArtifactMetaDataDto;
import io.apicurio.registry.storage.dto.ContentWrapperDto;
import io.apicurio.registry.storage.dto.StoredArtifactDto;
import io.apicurio.registry.storage.error.ArtifactNotFoundException;
import io.apicurio.registry.types.ArtifactMediaTypes;
import io.apicurio.registry.types.ArtifactState;
import io.apicurio.registry.types.ReferenceType;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.interceptor.Interceptors;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@ApplicationScoped
@Interceptors({ResponseErrorLivenessCheck.class, ResponseTimeoutReadinessCheck.class})
@Logged
public class IdsResourceImpl extends AbstractResourceImpl implements IdsResource {

    @Inject
    CommonResourceOperations common;

    private void checkIfDeprecated(Supplier<ArtifactState> stateSupplier, String artifactId, String version, Response.ResponseBuilder builder) {
        HeadersHack.checkIfDeprecated(stateSupplier, null, artifactId, version, builder);
    }

    /**
     * @see io.apicurio.registry.rest.v3.IdsResource#getContentById(long)
     */
    @Override
    @Authorized(style = AuthorizedStyle.None, level = AuthorizedLevel.Read)
    public Response getContentById(long contentId) {
        ContentHandle content = storage.getArtifactByContentId(contentId).getContent();
        Response.ResponseBuilder builder = Response.ok(content, ArtifactMediaTypes.BINARY);
        return builder.build();
    }

    /**
     * @see io.apicurio.registry.rest.v3.IdsResource#getContentByGlobalId(long, io.apicurio.registry.rest.v3.beans.HandleReferencesType)
     */
    @Override
    @Authorized(style = AuthorizedStyle.GlobalId, level = AuthorizedLevel.Read)
    public Response getContentByGlobalId(long globalId, HandleReferencesType references) {
        ArtifactMetaDataDto metaData = storage.getArtifactMetaData(globalId);
        if (ArtifactState.DISABLED.equals(metaData.getState())) {
            throw new ArtifactNotFoundException(null, String.valueOf(globalId));
        }

        if (references == null) {
            references = HandleReferencesType.PRESERVE;
        }

        StoredArtifactDto artifact = storage.getArtifactVersion(globalId);

        MediaType contentType = factory.getArtifactMediaType(metaData.getType());

        ContentHandle contentToReturn = artifact.getContent();
        handleContentReferences(references, metaData.getType(), contentToReturn, artifact.getReferences());

        Response.ResponseBuilder builder = Response.ok(contentToReturn, contentType);
        checkIfDeprecated(metaData::getState, metaData.getId(), metaData.getVersion(), builder);
        return builder.build();
    }

    /**
     * @see io.apicurio.registry.rest.v3.IdsResource#getContentByHash(java.lang.String)
     */
    @Override
    @Authorized(style = AuthorizedStyle.None, level = AuthorizedLevel.Read)
    public Response getContentByHash(String contentHash) {
        ContentHandle content = storage.getArtifactByContentHash(contentHash).getContent();
        Response.ResponseBuilder builder = Response.ok(content, ArtifactMediaTypes.BINARY);
        return builder.build();
    }

    /**
     * @see io.apicurio.registry.rest.v3.IdsResource#referencesByContentHash(java.lang.String)
     */
    @Override
    public List<ArtifactReference> referencesByContentHash(String contentHash) {
        return common.getReferencesByContentHash(contentHash);
    }

    /**
     * @see io.apicurio.registry.rest.v3.IdsResource#referencesByContentId(long)
     */
    @Override
    public List<ArtifactReference> referencesByContentId(long contentId) {
        ContentWrapperDto artifact = storage.getArtifactByContentId(contentId);
        return artifact.getReferences().stream()
                .map(V3ApiUtil::referenceDtoToReference)
                .collect(Collectors.toList());
    }

    /**
     * @see io.apicurio.registry.rest.v3.IdsResource#referencesByGlobalId(long, io.apicurio.registry.types.ReferenceType)
     */
    @Override
    public List<ArtifactReference> referencesByGlobalId(long globalId, ReferenceType refType) {
        if (refType == ReferenceType.OUTBOUND || refType == null) {
            StoredArtifactDto artifact = storage.getArtifactVersion(globalId);
            return artifact.getReferences().stream()
                    .map(V3ApiUtil::referenceDtoToReference)
                    .collect(Collectors.toList());
        } else {
            ArtifactMetaDataDto amd = storage.getArtifactMetaData(globalId);
            return storage.getInboundArtifactReferences(amd.getGroupId(), amd.getId(), amd.getVersion()).stream()
                    .map(V3ApiUtil::referenceDtoToReference)
                    .collect(Collectors.toList());
        }
    }
}