/*
 * Sleuth Kit CASE JSON LD Support
 *
 * Copyright 2020 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.caseuco;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import static org.sleuthkit.caseuco.StandardAttributeTypes.TSK_DEVICE_NAME;
import static org.sleuthkit.caseuco.StandardAttributeTypes.TSK_EMAIL_FROM;
import static org.sleuthkit.caseuco.StandardAttributeTypes.TSK_TEXT;

import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_CONTACT;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_DEVICE_ATTACHED;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_EMAIL_MSG;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_EXTRACTED_TEXT;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_GEN_INFO;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_HASHSET_HIT;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_INSTALLED_PROG;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_MESSAGE;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_METADATA_EXIF;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_OS_INFO;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_RECENT_OBJECT;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_SERVICE_ACCOUNT;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_WEB_BOOKMARK;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_WEB_COOKIE;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_WEB_DOWNLOAD;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_WEB_HISTORY;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_WEB_SEARCH_QUERY;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_ACCOUNT;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_BLUETOOTH_ADAPTER;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_BLUETOOTH_PAIRING;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_CALENDAR_ENTRY;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_CALLLOG;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_DATA_SOURCE_USAGE;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_DEVICE_INFO;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_ENCRYPTION_DETECTED;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_ENCRYPTION_SUSPECTED;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_GPS_BOOKMARK;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_GPS_LAST_KNOWN_LOCATION;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_GPS_ROUTE;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_GPS_SEARCH;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_INTERESTING_ARTIFACT_HIT;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_OBJECT_DETECTED;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_PROG_RUN;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_REMOTE_DRIVE;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_SIM_ATTACHED;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_SPEED_DIAL_ENTRY;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_VERIFICATION_FAILED;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_WIFI_NETWORK;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_WIFI_NETWORK_ADAPTER;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_CLIPBOARD_CONTENT;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_GPS_TRACK;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_METADATA;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_TL_EVENT;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_USER_CONTENT_SUSPECTED;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_WEB_CACHE;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_WEB_FORM_ADDRESS;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_ASSOCIATED_OBJECT;

import org.sleuthkit.datamodel.ContentTag;
import org.sleuthkit.datamodel.DataSource;
import org.sleuthkit.datamodel.FileSystem;
import org.sleuthkit.datamodel.Image;
import org.sleuthkit.datamodel.Pool;
import org.sleuthkit.datamodel.Volume;
import org.sleuthkit.datamodel.VolumeSystem;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.AccountFileInstance;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_KEYWORD_HIT;
import org.sleuthkit.datamodel.BlackboardAttribute;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_ACCOUNT_TYPE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_ASSOCIATED_ARTIFACT;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_CALENDAR_ENTRY_TYPE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_CARD_NUMBER;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_CATEGORY;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_COMMENT;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_COUNT;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME_ACCESSED;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME_CREATED;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME_END;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME_MODIFIED;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME_RCVD;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME_SENT;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME_START;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DESCRIPTION;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DEVICE_ID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DEVICE_MAKE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DEVICE_MODEL;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DIRECTION;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DISPLAY_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DOMAIN;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_EMAIL;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_EMAIL_BCC;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_EMAIL_CC;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_EMAIL_HOME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_EMAIL_OFFICE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_EMAIL_REPLYTO;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_FLAG;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_GEO_ALTITUDE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_GEO_LATITUDE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_GEO_LONGITUDE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_GEO_TRACKPOINTS;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_GROUPS;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_HASH_PHOTODNA;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_HEADERS;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_ICCID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_ID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_IMEI;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_IMSI;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_LAST_PRINTED_DATETIME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_LOCAL_PATH;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_LOCATION;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_MAC_ADDRESS;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_MSG_ID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_NAME_PERSON;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_ORGANIZATION;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_OWNER;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PASSWORD;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PATH;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PATH_SOURCE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PHONE_NUMBER;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PHONE_NUMBER_FROM;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PHONE_NUMBER_HOME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PHONE_NUMBER_MOBILE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PHONE_NUMBER_OFFICE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PHONE_NUMBER_TO;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PROCESSOR_ARCHITECTURE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PRODUCT_ID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PROG_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_REMOTE_PATH;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_SET_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_SSID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_SUBJECT;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_TEMP_DIR;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_TL_EVENT_TYPE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_URL;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_USER_ID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_USER_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_VALUE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_VERSION;
import org.sleuthkit.datamodel.CommunicationsManager;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.Score;
import org.sleuthkit.datamodel.TimelineEventType;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.attributes.BlackboardJsonAttrUtil;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPoints;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskData.DbType;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper.MessageReadStatus;

/**
 * Exports Sleuth Kit DataModel objects to CASE. The CASE JSON output is
 * configured to be serialized with Gson. Each export method will produce a list
 * of CASE JSON objects. Clients should loop through this list and write these
 * objects to any OutputStream via Gson. See the Gson documentation for more
 * information on object serialization.
 *
 * NOTE: The exporter behavior can be configured by passing configuration
 * parameters in a custom Properties instance. A list of available configuration
 * properties can be found in the README.md file.
 */
public class CaseUcoImporter {

    private static class AddedItem {

        private final long objectId;
        private final String caseUcoId;
        private final Content content;

        public AddedItem(long objectId, String caseUcoId, Content content) {
            this.objectId = objectId;
            this.caseUcoId = caseUcoId;
            this.content = content;
        }

        public long getObjectId() {
            return objectId;
        }

        public String getCaseUcoId() {
            return caseUcoId;
        }

        public Content getContent() {
            return content;
        }
    }

    private static class IdMapping {

        private final Map<String, Long> mapping = new HashMap<String, Long>();

        void addContent(String caseUcoId, Content content) {
            mapping.put(caseUcoId, content.getId());
        }

        Long getId(String caseUcoId) {
            return mapping.get(caseUcoId);
        }
    }

    private static interface ArtifactContext {

        Content getParentContent();

        Long getDataSourceId();
    }

    @SuppressWarnings("deprecation")
    private static final BlackboardArtifact.Type TSK_OS_ACCOUNT = new BlackboardArtifact.Type(ARTIFACT_TYPE.TSK_OS_ACCOUNT);

    private static final String INCLUDE_PARENT_CHILD_RELATIONSHIPS_PROP = "exporter.relationships.includeParentChild";
    private static final String DEFAULT_PARENT_CHILD_RELATIONSHIPS_VALUE = "true";
    private static final String CASE_UCO_SOURCE = "Case Uco Importer";
    private static final String CONTAINED_WITHIN_RELATIONSHIP = "contained-within";

    private static final Map<String, BlackboardAttribute.Type> EMAIL_MSG_TYPES = Collections.unmodifiableMap(new HashMap<>() {{
        put("text/html", TSK_EMAIL_CONTENT_HTML);
        put("text/rtf", TSK_EMAIL_CONTENT_PLAIN);
        put("text/plain", TSK_EMAIL_CONTENT_RTF);
    }});
        
    private final Map<String, TimelineEventType> eventTypeMapping;

    private final Gson gson;
    private final SleuthkitCase sleuthkitCase;

    /**
     * Creates a default CaseUcoExporter.
     *
     * @param sleuthkitCase The sleuthkit case instance containing the data to
     *                      be exported.
     */
    public CaseUcoImporter(SleuthkitCase sleuthkitCase) {
        this.sleuthkitCase = sleuthkitCase;
        Map<String, TimelineEventType> eventTypeMapping = null;
        try {
            eventTypeMapping = sleuthkitCase.getTimelineManager().getEventTypes().stream()
                    .collect(Collectors.toMap(evtType -> evtType.getDisplayName(), evtType -> evtType, (evt1, evt2) -> evt1));

        } catch (TskCoreException ex) {
            Logger.getLogger(CaseUcoImporter.class.getName()).log(Level.SEVERE, null, ex);
        }
        this.eventTypeMapping = eventTypeMapping;

        this.gson = new GsonBuilder()
                .registerTypeAdapter(Facet.class, new FacetDeserializer())
                .create();
    }

    /**
     * Exports the SleuthkitCase instance passed during initialization to CASE.
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportSleuthkitCase() throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        String caseDirPath = sleuthkitCase
                .getDbDirPath()
                .replaceAll("\\\\", "/");

        Trace export = new Trace(this.uuidService.createUUID(sleuthkitCase));

        if (sleuthkitCase.getDatabaseType().equals(DbType.POSTGRESQL)) {
            export.addBundle(new File()
                    .setFilePath(caseDirPath)
                    .setIsDirectory(true));
        } else {
            export.addBundle(new File()
                    .setFilePath(caseDirPath + "/" + sleuthkitCase.getDatabaseName())
                    .setIsDirectory(false));
        }

        addToOutput(export, output);
        return output;
    }

    /**
     * Exports an AbstractFile instance to CASE.
     *
     * @param file AbstractFile instance to export
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportAbstractFile(AbstractFile file) throws TskCoreException {
        return exportAbstractFile(file, null);
    }

    /**
     * Exports an AbstractFile instance to CASE.
     *
     * @param file      AbstractFile instance to export
     * @param localPath The location of the file on secondary storage, somewhere
     *                  other than the case. Example: local disk. This value
     *                  will be ignored if null
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportAbstractFile(AbstractFile file, String localPath) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        ContentData contentData = new ContentData()
                .setMimeType(file.getMIMEType())
                .setSizeInBytes(file.getSize())
                .setMd5Hash(file.getMd5Hash());

        if (localPath != null) {
            Trace localPathTrace = new BlankTraceNode()
                    .addBundle(new URL()
                            .setFullValue(localPath));
            contentData.setDataPayloadReferenceUrl(localPathTrace);

            addToOutput(localPathTrace, output);
        }

        File fileExport = new File()
                .setAccessedTime(file.getAtime())
                .setExtension(file.getNameExtension())
                .setFileName(file.getName())
                .setFilePath(file.getUniquePath())
                .setIsDirectory(file.isDir())
                .setSizeInBytes(file.getSize());
        fileExport.setModifiedTime(file.getMtime());
        fileExport.setCreatedTime(file.getCrtime());

        Trace export = new Trace(this.uuidService.createUUID(file))
                .addBundle(contentData)
                .addBundle(fileExport);

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(file.getDataSource()));

        return output;
    }

    /**
     * Exports a ContentTag instance to CASE.
     *
     * @param contentTag ContentTag instance to export
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportContentTag(ContentTag contentTag) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Annotation annotation = new Annotation(this.uuidService.createUUID(contentTag))
                .addObject(this.uuidService.createUUID(contentTag.getContent()));
        annotation.setDescription(contentTag.getComment());
        annotation.addTag(contentTag.getName().getDisplayName());

        addToOutput(annotation, output);
        return output;
    }

    /**
     * Exports a DataSource instance to CASE.
     *
     * @param dataSource DataSource instance to export
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportDataSource(DataSource dataSource) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Trace export = new Trace(this.uuidService.createUUID(dataSource))
                .addBundle(new File()
                        .setFilePath(getDataSourcePath(dataSource)))
                .addBundle(new ContentData()
                        .setSizeInBytes(dataSource.getSize()));

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(this.sleuthkitCase));

        return output;
    }

    String getDataSourcePath(DataSource dataSource) {
        String dataSourcePath = "";
        if (dataSource instanceof Image) {
            String[] paths = ((Image) dataSource).getPaths();
            if (paths.length > 0) {
                dataSourcePath = paths[0];
            }
        } else {
            dataSourcePath = dataSource.getName();
        }
        dataSourcePath = dataSourcePath.replaceAll("\\\\", "/");
        return dataSourcePath;
    }

    /**
     * Exports a FileSystem instance to CASE.
     *
     * @param fileSystem FileSystem instance to export
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportFileSystem(FileSystem fileSystem) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Trace export = new Trace(this.uuidService.createUUID(fileSystem))
                .addBundle(new org.sleuthkit.caseuco.FileSystem()
                        .setFileSystemType(fileSystem.getFsType())
                        .setCluserSize(fileSystem.getBlock_size()));

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(fileSystem.getParent()));

        return output;
    }

    /**
     * Exports a Pool instance to CASE.
     *
     * @param pool Pool instance to export
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportPool(Pool pool) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Trace export = new Trace(this.uuidService.createUUID(pool))
                .addBundle(new ContentData()
                        .setSizeInBytes(pool.getSize()));

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(pool.getParent()));

        return output;
    }

    /**
     * Exports a Volume instance to CASE.
     *
     * @param volume Volume instance to export
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportVolume(Volume volume) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Trace export = new Trace(this.uuidService.createUUID(volume));
        org.sleuthkit.caseuco.Volume volumeFacet = new org.sleuthkit.caseuco.Volume();
        if (volume.getLength() > 0) {
            volumeFacet.setSectorSize(volume.getSize() / volume.getLength());
        }
        export.addBundle(volumeFacet)
                .addBundle(new ContentData()
                        .setSizeInBytes(volume.getSize()));

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(volume.getParent()));

        return output;

    }

    /**
     * Exports a VolumeSystem instance to CASE.
     *
     * @param volumeSystem VolumeSystem instance to export
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException If an error occurred during database access.
     */
    public List<JsonElement> exportVolumeSystem(VolumeSystem volumeSystem) throws TskCoreException {
        List<JsonElement> output = new ArrayList<>();

        Trace export = new Trace(this.uuidService.createUUID(volumeSystem))
                .addBundle(new ContentData()
                        .setSizeInBytes(volumeSystem.getSize()));

        addToOutput(export, output);
        addParentChildRelationship(output, export.getId(),
                this.uuidService.createUUID(volumeSystem.getParent()));

        return output;
    }

    /**
     * Exports a BlackboardArtifact instance to CASE.
     *
     * @param artifact BlackboardArtifact instance to export
     *
     * @return A collection of CASE JSON elements
     *
     * @throws TskCoreException                            If an error occurred
     *                                                     during database
     *                                                     access.
     * @throws ContentNotExportableException               if the content could
     *                                                     not be exported, even
     *                                                     in part, to CASE.
     * @throws BlackboardJsonAttrUtil.InvalidJsonException If a JSON valued
     *                                                     attribute could not
     *                                                     be correctly
     *                                                     deserialized.
     */
    @SuppressWarnings("deprecation")
    public List<JsonElement> exportBlackboardArtifact(BlackboardArtifact artifact) throws TskCoreException,
            ContentNotExportableException, BlackboardJsonAttrUtil.InvalidJsonException {
        List<JsonElement> output = new ArrayList<>();

        String uuid = this.uuidService.createUUID(artifact);
        int artifactTypeId = artifact.getArtifactTypeID();

        if (TSK_GEN_INFO.getTypeID() == artifactTypeId) {
            assembleGenInfo(uuid, artifact, output);
        } else if (TSK_WEB_BOOKMARK.getTypeID() == artifactTypeId) {
            assembleWebBookmark(uuid, artifact, output);
        } else if (TSK_WEB_COOKIE.getTypeID() == artifactTypeId) {
            assembleWebCookie(uuid, artifact, output);
        } else if (TSK_WEB_HISTORY.getTypeID() == artifactTypeId) {
            assembleWebHistory(uuid, artifact, output);
        } else if (TSK_WEB_DOWNLOAD.getTypeID() == artifactTypeId) {
            assembleWebDownload(uuid, artifact, output);
        } else if (TSK_RECENT_OBJECT.getTypeID() == artifactTypeId) {
            assembleRecentObject(uuid, artifact, output);
        } else if (TSK_INSTALLED_PROG.getTypeID() == artifactTypeId) {
            assembleInstalledProg(uuid, artifact, output);
        } else if (TSK_HASHSET_HIT.getTypeID() == artifactTypeId) {
            assembleHashsetHit(uuid, artifact, output);
        } else if (TSK_DEVICE_ATTACHED.getTypeID() == artifactTypeId) {
            assembleDeviceAttached(uuid, artifact, output);
        } else if (TSK_INTERESTING_FILE_HIT.getTypeID() == artifactTypeId) {
            assembleInterestingFileHit(uuid, artifact, output);
        } else if (TSK_EMAIL_MSG.getTypeID() == artifactTypeId) {
            assembleEmailMessage(uuid, artifact, output);
        } else if (TSK_EXTRACTED_TEXT.getTypeID() == artifactTypeId) {
            assembleExtractedText(uuid, artifact, output);
        } else if (TSK_WEB_SEARCH_QUERY.getTypeID() == artifactTypeId) {
            assembleWebSearchQuery(uuid, artifact, output);
        } else if (TSK_METADATA_EXIF.getTypeID() == artifactTypeId) {
            assembleMetadataExif(uuid, artifact, output);
        } else if (TSK_OS_INFO.getTypeID() == artifactTypeId) {
            assembleOsInfo(uuid, artifact, output);
        } else if (TSK_OS_ACCOUNT.getTypeID() == artifactTypeId) {
            assembleOsAccount(uuid, artifact, output);
        } else if (TSK_SERVICE_ACCOUNT.getTypeID() == artifactTypeId) {
            assembleServiceAccount(uuid, artifact, output);
        } else if (TSK_CONTACT.getTypeID() == artifactTypeId) {
            assembleContact(uuid, artifact, output);
        } else if (TSK_MESSAGE.getTypeID() == artifactTypeId) {
            assembleMessage(uuid, artifact, output);
        } else if (TSK_CALLLOG.getTypeID() == artifactTypeId) {
            assembleCallog(uuid, artifact, output);
        } else if (TSK_CALENDAR_ENTRY.getTypeID() == artifactTypeId) {
            assembleCalendarEntry(uuid, artifact, output);
        } else if (TSK_SPEED_DIAL_ENTRY.getTypeID() == artifactTypeId) {
            assembleSpeedDialEntry(uuid, artifact, output);
        } else if (TSK_BLUETOOTH_PAIRING.getTypeID() == artifactTypeId) {
            assembleBluetoothPairing(uuid, artifact, output);
        } else if (TSK_GPS_BOOKMARK.getTypeID() == artifactTypeId) {
            assembleGpsBookmark(uuid, artifact, output);
        } else if (TSK_GPS_LAST_KNOWN_LOCATION.getTypeID() == artifactTypeId) {
            assembleGpsLastKnownLocation(uuid, artifact, output);
        } else if (TSK_GPS_SEARCH.getTypeID() == artifactTypeId) {
            assembleGpsSearch(uuid, artifact, output);
        } else if (TSK_PROG_RUN.getTypeID() == artifactTypeId) {
            assembleProgRun(uuid, artifact, output);
        } else if (TSK_ENCRYPTION_DETECTED.getTypeID() == artifactTypeId) {
            assembleEncryptionDetected(uuid, artifact, output);
        } else if (TSK_INTERESTING_ARTIFACT_HIT.getTypeID() == artifactTypeId) {
            assembleInterestingArtifact(uuid, artifact, output);
        } else if (TSK_GPS_ROUTE.getTypeID() == artifactTypeId) {
            assembleGPSRoute(uuid, artifact, output);
        } else if (TSK_REMOTE_DRIVE.getTypeID() == artifactTypeId) {
            assembleRemoteDrive(uuid, artifact, output);
        } else if (TSK_ACCOUNT.getTypeID() == artifactTypeId) {
            assembleAccount(uuid, artifact, output);
        } else if (TSK_ENCRYPTION_SUSPECTED.getTypeID() == artifactTypeId) {
            assembleEncryptionSuspected(uuid, artifact, output);
        } else if (TSK_OBJECT_DETECTED.getTypeID() == artifactTypeId) {
            assembleObjectDetected(uuid, artifact, output);
        } else if (TSK_WIFI_NETWORK.getTypeID() == artifactTypeId) {
            assembleWifiNetwork(uuid, artifact, output);
        } else if (TSK_DEVICE_INFO.getTypeID() == artifactTypeId) {
            assembleDeviceInfo(uuid, artifact, output);
        } else if (TSK_SIM_ATTACHED.getTypeID() == artifactTypeId) {
            assembleSimAttached(uuid, artifact, output);
        } else if (TSK_BLUETOOTH_ADAPTER.getTypeID() == artifactTypeId) {
            assembleBluetoothAdapter(uuid, artifact, output);
        } else if (TSK_WIFI_NETWORK_ADAPTER.getTypeID() == artifactTypeId) {
            assembleWifiNetworkAdapter(uuid, artifact, output);
        } else if (TSK_VERIFICATION_FAILED.getTypeID() == artifactTypeId) {
            assembleVerificationFailed(uuid, artifact, output);
        } else if (TSK_DATA_SOURCE_USAGE.getTypeID() == artifactTypeId) {
            assembleDataSourceUsage(uuid, artifact, output);
        } else if (TSK_WEB_FORM_ADDRESS.getTypeID() == artifactTypeId) {
            assembleWebFormAddress(uuid, artifact, output);
        } else if (TSK_WEB_CACHE.getTypeID() == artifactTypeId) {
            assembleWebCache(uuid, artifact, output);
        } else if (TSK_TL_EVENT.getTypeID() == artifactTypeId) {
            assembleTimelineEvent(uuid, artifact, output);
        } else if (TSK_CLIPBOARD_CONTENT.getTypeID() == artifactTypeId) {
            assembleClipboardContent(uuid, artifact, output);
        } else if (TSK_ASSOCIATED_OBJECT.getTypeID() == artifactTypeId) {
            assembleAssociatedObject(uuid, artifact, output);
        } else if (TSK_USER_CONTENT_SUSPECTED.getTypeID() == artifactTypeId) {
            assembleUserContentSuspected(uuid, artifact, output);
        } else if (TSK_METADATA.getTypeID() == artifactTypeId) {
            assembleMetadata(uuid, artifact, output);
        } else if (TSK_GPS_TRACK.getTypeID() == artifactTypeId) {
            assembleGpsTrack(uuid, artifact, output);
        }

        if (output.isEmpty()) {
            throw new ContentNotExportableException(String.format(
                    "Artifact [id:%d, type:%d] is either not supported "
                    + "or did not have any exported attributes.", artifact.getId(), artifactTypeId));
        }

        addParentChildRelationship(output, uuid,
                this.uuidService.createUUID(artifact.getParent()));

        return output;
    }

    private Optional<BlackboardArtifact> importWebCookie(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);
        
        Optional<URL> url = childMap.getChild(URL.class);
        Optional<ContentData> contentData = childMap.getChild(ContentData.class);
        Optional<BrowserCookie> browserCookie = childMap.getChild(BrowserCookie.class);
        
        Optional<DomainName> domainName = browserCookie
                .flatMap(b -> Optional.ofNullable(b.getCookieDomain()))
                .flatMap(id -> getByUcoId(mapping, id, Trace.class))
                .flatMap(t -> getChild(t, DomainName.class));

        Optional<Application> application = browserCookie
                .flatMap(b -> Optional.ofNullable(b.getApplication()))
                .flatMap(id -> getByUcoId(mapping, id, Trace.class))
                .flatMap(t -> getChild(t, Application.class));

        if (!url.isPresent() || !contentData.isPresent() || !browserCookie.isPresent() || !domainName.isPresent() || !application.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> urlAttr = url.flatMap(u -> getAttr(TSK_URL, u.getFullValue()));
        Optional<BlackboardAttribute> valueAttr = contentData.flatMap(c -> getAttr(TSK_VALUE, c.getDataPayload()));
        Optional<BlackboardAttribute> nameAttr = browserCookie.flatMap(c -> getAttr(TSK_PROG_NAME, c.getCookieName()));
        
        if (!urlAttr.isPresent() || !valueAttr.isPresent() || !nameAttr.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> progNameAttr = application.flatMap(a -> getAttr(TSK_PROG_NAME, a.getApplicationIdentifier()));
        Optional<BlackboardAttribute> domainAttr = domainName.flatMap(d -> getAttr(TSK_DOMAIN, d.getValue()));
        Optional<BlackboardAttribute> timeStartAttr = browserCookie.flatMap(c -> getTimeStampAttr(TSK_DATETIME_START, c.getAccessedTime()));
        Optional<BlackboardAttribute> timeEndAttr = browserCookie.flatMap(c -> getTimeStampAttr(TSK_DATETIME_END, c.getExpirationTime()));
        Optional<BlackboardAttribute> timeCreatedAttr = browserCookie.flatMap(c -> getTimeStampAttr(TSK_DATETIME_CREATED, c.getCreatedTime()));
        
        return newArtifact(content, TSK_WEB_COOKIE, getFiltered(urlAttr, valueAttr, nameAttr, progNameAttr, domainAttr, timeStartAttr, timeEndAttr, timeCreatedAttr));
    }

    private Optional<BlackboardArtifact> importWebBookmark(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);
        
        Optional<BrowserBookmark> bookmark = childMap.getChild(BrowserBookmark.class);
        Optional<DomainName> domain = childMap.getChild(DomainName.class);
        Optional<Application> application = bookmark
                .flatMap(b -> Optional.ofNullable(b.getApplication()))
                .flatMap(id -> getByUcoId(mapping, id, Trace.class))
                .flatMap(t -> getChild(t, Application.class));
        
        if (!bookmark.isPresent() || !domain.isPresent() || !application.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> urlAttr = bookmark.flatMap(b -> getAttr(TSK_URL, b.getUrlTargeted()));
        
        if (!urlAttr.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> nameAttr = bookmark.flatMap(b -> getAttr(TSK_NAME, b.getName()));
        Optional<BlackboardAttribute> dateTimeAttr = bookmark.flatMap(b -> getTimeStampAttr(TSK_DATETIME_CREATED, b.getCreatedTime()));
        
        Optional<BlackboardAttribute> domainAttr = domain.flatMap(d -> getAttr(TSK_DOMAIN, d.getValue()));
        Optional<BlackboardAttribute> appAttr = application.flatMap(a -> getAttr(TSK_PROG_NAME, a.getApplicationIdentifier()));
        
        return newArtifact(content, TSK_WEB_BOOKMARK, getFiltered(nameAttr, dateTimeAttr, domainAttr, appAttr));
    }

    private Optional<BlackboardArtifact> importGenInfo(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        Optional<Hash> hash = getAs(ucoObject, Hash.class);

        if (!hash.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> photoDna = hash.flatMap(h -> getAttr(TSK_HASH_PHOTODNA, h.getId()));
        
        return newArtifact(content, TSK_GEN_INFO, getFiltered(photoDna));
    }

    private Optional<BlackboardArtifact> importWebHistory(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);
        
        Optional<URL> url = childMap.getChild(URL.class);
        Optional<DomainName> domain = childMap.getChild(DomainName.class);
        Optional<Application> application = childMap.getChild(Application.class);
        Optional<IdentityFacet> identityFacet = url
                .flatMap(u -> Optional.ofNullable(u.getUserName()))
                .flatMap(id -> getByUcoId(mapping, id, Trace.class))
                .flatMap(t -> getChild(t, IdentityFacet.class));
        
        if (!url.isPresent() || !domain.isPresent() || !application.isPresent() || !identityFacet.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> urlAttr = url.flatMap(u -> getAttr(TSK_URL, u.getFullValue()));
        
        if (!urlAttr.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> userName = identityFacet.flatMap(i -> getAttr(TSK_USER_NAME. i.getName()));
        Optional<BlackboardAttribute> domainAttr = domain.flatMap(d -> getAttr(TSK_DOMAIN, d.getValue()));
        Optional<BlackboardAttribute> appAttr = application.flatMap(a -> getAttr(TSK_PROG_NAME, a.getApplicationIdentifier()));
        
        return newArtifact(content, TSK_WEB_HISTORY, getFiltered(userName, urlAttr, domainAttr, appAttr));
    }

    private Optional<BlackboardArtifact> importWebDownload(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);
        
        Optional<URL> url = childMap.getChild(URL.class);
        Optional<DomainName> domain = childMap.getChild(DomainName.class);
        Optional<File> file = childMap.getChild(File.class);
        Optional<Application> application = childMap.getChild(Application.class);
        
        if (!url.isPresent() || !domain.isPresent() || !file.isPresent() || !application.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> urlAttr = url.flatMap(u -> getAttr(TSK_URL, u.getFullValue()));
        
        if (!urlAttr.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> domainAttr = domain.flatMap(d -> getAttr(TSK_DOMAIN, d.getValue()));
        Optional<BlackboardAttribute> pathAttr = file.flatMap(f -> getAttr(TSK_PATH, f.getFilePath()));
        Optional<BlackboardAttribute> appAttr = application.flatMap(a -> getAttr(TSK_PROG_NAME, a.getApplicationIdentifier()));
        
        return newArtifact(content, TSK_WEB_DOWNLOAD, getFiltered(urlAttr, domainAttr, pathAttr, appAttr));
    }

    private Optional<BlackboardArtifact> importDeviceAttached(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);
        
        Optional<Device> device = childMap.getChild(Device.class);
        Optional<MACAddress> macAddress = childMap.getChild(MACAddress.class);

        if (!device.isPresent() || !macAddress.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> deviceId = device.flatMap((dev) -> getAttr(TSK_DEVICE_MODEL, dev.getModel()));
        
        if (!deviceId.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> deviceMake = device.flatMap((dev) -> getAttr(TSK_DEVICE_MAKE, dev.getManufacturer()));
        Optional<BlackboardAttribute> deviceModel = device.flatMap((dev) -> getAttr(TSK_DEVICE_MODEL, dev.getModel()));
        Optional<BlackboardAttribute> macAddressAttr = macAddress.flatMap((m) -> getAttr(TSK_MAC_ADDRESS, m.getValue()));
        Optional<BlackboardAttribute> dateTime = getTimeStampAttr(TSK_DATETIME, trace.getCreatedTime());
        
        return newArtifact(content, TSK_DEVICE_ATTACHED, getFiltered(deviceId, deviceMake, deviceModel, macAddressAttr, dateTime));
        
    }

    private Optional<BlackboardArtifact> importHashsetHit(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // only distinguished by assertion requiring a name
        
        Optional<Assertion> assertion = getAs(ucoObject, Assertion.class);
        Optional<BlackboardAttribute> setNameAttr = assertion.flatMap(a -> getAttr(TSK_SET_NAME, a.getName()));
        
        if (!setNameAttr.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> commentAttr = assertion.flatMap(a -> getAttr(TSK_COMMENT, a.getStatement()));
        
        return newArtifact(content, TSK_HASHSET_HIT, getFiltered(setNameAttr, commentAttr));
    }

    
    private Optional<BlackboardArtifact> importInstalledProg(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }
        
        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);
        
        List<File> files = childMap.getChildren(File.class);
        Optional<Software> softwareOpt = childMap.getChild(Software.class);
        
        if (files.size() < 2 || !softwareOpt.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> progName = softwareOpt.flatMap(s -> getAttr(TSK_PROG_NAME, s.getName()));
        
        if (!progName.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> pathSource = getAttr(TSK_PATH_SOURCE, files.get(0).getFilePath());
        
        Optional<BlackboardAttribute> path = getAttr(TSK_PATH, files.get(1).getFilePath());
        Optional<BlackboardAttribute> dateTime = getTimeStampAttr(TSK_DATETIME, files.get(1).getModifiedTime());
        Optional<BlackboardAttribute> createdDateTime = getTimeStampAttr(TSK_DATETIME_CREATED, files.get(1).getCreatedTime());
        
        return newArtifact(content, TSK_INSTALLED_PROG, getFiltered(pathSource, progName, path, dateTime, createdDateTime));
    }

    
    private Optional<BlackboardArtifact> importRecentObject(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // doesn't have a TSK_PATH 
        
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }
        
        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);
        
        Optional<Application> applicationOpt = childMap.getChild(Application.class);
        Optional<WindowsRegistryValue> winRegOpt = childMap.getChild(WindowsRegistryValue.class);
        Optional<File> fileOpt = childMap.getChild(File.class);
        
        Optional<Assertion> assertOpt = getSourcesFromTarget(mapping, trace.getId(), Assertion.class).stream()
                .filter(a -> a.getStatement() != null)
                .findFirst();
        
        if (!applicationOpt.isPresent() || !winRegOpt.isPresent() || !fileOpt.isPresent() || !assertOpt.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> progName = applicationOpt.flatMap(a -> getAttr(TSK_PROG_NAME, a.getApplicationIdentifier()));
        
        Optional<BlackboardAttribute> value = winRegOpt.flatMap(reg -> getAttr(TSK_VALUE, reg.getData()));
        Optional<BlackboardAttribute> name = winRegOpt.flatMap(reg -> getAttr(TSK_NAME, reg.getName()));
        
        Optional<BlackboardAttribute> accessedDate = fileOpt.flatMap(f -> getTimeStampAttr(TSK_DATETIME_ACCESSED, f.getAccessedTime()));
        Optional<BlackboardAttribute> date = fileOpt.flatMap(f -> getTimeStampAttr(TSK_DATETIME, f.getCreatedTime()));
        
        Optional<BlackboardAttribute> comment = assertOpt.flatMap(a -> getAttr(TSK_COMMENT, a.getStatement()));
        
        return newArtifact(content, TSK_RECENT_OBJECT, getFiltered(progName, value, name, accessedDate, date, comment));
    }

    private Optional<BlackboardArtifact> importInterestingFileHit(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // only distinguished by assertion requiring a name
        
        Optional<Assertion> assertion = getAs(ucoObject, Assertion.class);
        Optional<BlackboardAttribute> setNameAttr = assertion.flatMap(a -> getAttr(TSK_SET_NAME, a.getName()));
        
        if (!setNameAttr.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> commentAttr = assertion.flatMap(a -> getAttr(TSK_COMMENT, a.getStatement()));
        
        return newArtifact(content, TSK_INTERESTING_FILE_HIT, getFiltered(setNameAttr, commentAttr));
    }

    
    private Optional<BlackboardArtifact> importEmailMessage(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {       
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);
        
        Optional<EmailMessage> emailMsgOpt = childMap.getChild(EmailMessage.class);
        Optional<File> file = childMap.getChild(File.class);
        
        if (!emailMsgOpt.isPresent() || !file.isPresent()) {
            return Optional.empty();
        }
        
        EmailMessage emailMsg = emailMsgOpt.get();
        
        Optional<BlackboardAttribute> emailMsgAttr = Optional.ofNullable(emailMsg.getContentType())
                .flatMap(tp -> Optional.ofNullable(EMAIL_MSG_TYPES.get(tp)))
                .flatMap(attrType -> getAttr(attrType, emailMsg.getBody()));
        
        if (!emailMsgAttr.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> timeReceivedAttr = getTimeStampAttr(TSK_DATETIME_RCVD, emailMsg.getReceivedTime());
        Optional<BlackboardAttribute> timeSentAttr = getTimeStampAttr(TSK_DATETIME_SENT, emailMsg.getSentTime());
        Optional<BlackboardAttribute> msgIdAttr = getAttr(TSK_MSG_ID, emailMsg.getMessageID());
        Optional<BlackboardAttribute> subjectAttr = getAttr(TSK_SUBJECT, emailMsg.getSubject());

        Optional<BlackboardAttribute> pathAttr = file.flatMap(f -> getAttr(TSK_PATH, f.getFilePath()));
        
        Optional<BlackboardAttribute> headerAttr = Optional.ofNullable(emailMsg.getHeaderRaw())
                .flatMap(headerId -> getByUcoId(mapping, headerId, Trace.class))
                .flatMap(t -> getChild(t, ExtractedString.class))
                .flatMap(es -> getAttr(TSK_HEADERS, es.getStringValue()));
        
        Optional<BlackboardAttribute> bccAttr = Optional.ofNullable(emailMsg.getBcc())
                    .flatMap(msgAddrId -> getByUcoId(mapping, msgAddrId, Trace.class))
                    .flatMap(t -> getChild(t, EmailAddress.class))
                    .flatMap(ea -> getAttr(TSK_EMAIL_BCC, ea.getValue()));
        
        Optional<BlackboardAttribute> ccAttr = Optional.ofNullable(emailMsg.getCc())
                    .flatMap(msgAddrId -> getByUcoId(mapping, msgAddrId, Trace.class))
                    .flatMap(t -> getChild(t, EmailAddress.class))
                    .flatMap(ea -> getAttr(TSK_EMAIL_CC, ea.getValue()));
        
        Optional<BlackboardAttribute> fromAttr = Optional.ofNullable(emailMsg.getFrom())
                    .flatMap(msgAddrId -> getByUcoId(mapping, msgAddrId, Trace.class))
                    .flatMap(t -> getChild(t, EmailAddress.class))
                    .flatMap(ea -> getAttr(TSK_EMAIL_FROM, ea.getValue()));
        
        return newArtifact(content, TSK_EMAIL_MSG, 
                getFiltered(emailMsgAttr, timeReceivedAttr, timeSentAttr, msgIdAttr, 
                        subjectAttr, pathAttr, headerAttr, bccAttr, ccAttr, fromAttr));
    }

    private Optional<BlackboardArtifact> importWebSearchQuery(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);
        
        Optional<Application> application = childMap.getChild(ApplicationAccount.class)
                .flatMap(appAcct -> Optional.ofNullable(appAcct.getApplication()))
                .flatMap(appId -> getByUcoId(mapping, appId, Trace.class))
                .flatMap(t -> getChild(t, Application.class));
        
        Optional<Note> note = childMap.getChild(Note.class);
        Optional<Domain> domain = childMap.getChild(Domain.class);
        
        if (Stream.of(application, note, domain).anyMatch(o -> !o.isPresent())) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> textAttr = note.flatMap(n -> getAttr(TSK_TEXT, n.getText()));
        if (!textAttr.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> progNameAttr = application.flatMap(a -> getAttr(TSK_PROG_NAME, a.getApplicationIdentifier()));
        Optional<BlackboardAttribute> domainAttr = domain.flatMap(d -> getAttr(TSK_DOMAIN, d.getValue()));
        
        return newArtifact(content, TSK_WEB_SEARCH_QUERY, getFiltered(progNameAttr, textAttr, domainAttr));
    }

    private Optional<BlackboardArtifact> importOsInfo(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);

        Optional<OperatingSystem> operatingSystem = childMap.getChild(OperatingSystem.class);
        Optional<DomainName> domainName = childMap.getChild(DomainName.class);
        Optional<Device> device = childMap.getChild(Device.class);
        Optional<ComputerSpecification> computerSpec = childMap.getChild(ComputerSpecification.class);
        Optional<WindowsComputerSpecification> winComputerSpec = childMap.getChild(WindowsComputerSpecification.class);

        Optional<Identity> registeredOwner = winComputerSpec
                .flatMap(winSpec -> Optional.ofNullable(winSpec.getRegisteredOwner()))
                .flatMap(registeredOwnerId -> getByUcoId(mapping, registeredOwnerId, Identity.class));

        Optional<Identity> registeredOrganization = winComputerSpec
                .flatMap(winSpec -> Optional.ofNullable(winSpec.getRegisteredOrganization()))
                .flatMap(registeredOrgId -> getByUcoId(mapping, registeredOrgId, Identity.class));

        Optional<EnvironmentVariable> tempDirEnvVar = winComputerSpec
                .flatMap(winSpec -> Optional.ofNullable(winSpec.getWindowsTempDirectory()))
                .flatMap(tempId -> getByUcoId(mapping, tempId, Trace.class))
                .flatMap(t -> getChild(t, EnvironmentVariable.class));
        
        if (Stream.of(operatingSystem, domainName, device, computerSpec, winComputerSpec, 
                registeredOwner, registeredOrganization, tempDirEnvVar).anyMatch(o -> !o.isPresent())) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> progNameAttr = operatingSystem.flatMap(o -> getAttr(TSK_PROG_NAME, o.getName()));
        
        if (!progNameAttr.isPresent()) {
            return Optional.empty();
        }
        
        Optional<BlackboardAttribute> ownerAttr = registeredOwner.flatMap(o -> getAttr(TSK_OWNER, o.getName()));
        Optional<BlackboardAttribute> orgAttr = registeredOrganization.flatMap(o -> getAttr(TSK_ORGANIZATION, o.getName()));
        Optional<BlackboardAttribute> tempAttr = tempDirEnvVar.flatMap(t -> getAttr(TSK_TEMP_DIR, t.getName()));
        Optional<BlackboardAttribute> dateTimeAttr = operatingSystem.flatMap(o -> getTimeStampAttr(TSK_DATETIME, o.getInstallDate()));
        Optional<BlackboardAttribute> versionAttr = operatingSystem.flatMap(o -> getAttr(TSK_VERSION, o.getVersion()));
        Optional<BlackboardAttribute> tempDirAttr = tempDirEnvVar.flatMap(o -> getAttr(TSK_TEMP_DIR, o.getValue()));
        Optional<BlackboardAttribute> domainAttr = domainName.flatMap(o -> getAttr(TSK_DOMAIN, o.getValue()));
        Optional<BlackboardAttribute> productIdAttr = device.flatMap(o -> getAttr(TSK_PRODUCT_ID, o.getSerialNumber()));
        Optional<BlackboardAttribute> nameAttr = computerSpec.flatMap(c -> getAttr(TSK_NAME, c.getName()));
        Optional<BlackboardAttribute> architectureAttr = computerSpec.flatMap(c -> getAttr(TSK_PROCESSOR_ARCHITECTURE, c.getProcessorArchitecture()));

        return newArtifact(content, TSK_OS_INFO,
                getFiltered(ownerAttr, orgAttr, tempAttr, dateTimeAttr, versionAttr, progNameAttr,
                        tempDirAttr, domainAttr, productIdAttr, nameAttr, architectureAttr));
    }

    private Optional<BlackboardArtifact> importOsAccount(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);

        Optional<EmailAddress> emailAddr = childMap.getChild(EmailAddress.class);
        Optional<PathRelation> pathRel = childMap.getChild(PathRelation.class);
        Optional<WindowsAccount> windowsAcct = childMap.getChild(WindowsAccount.class);
        Optional<DigitalAccount> digitalAcct = childMap.getChild(DigitalAccount.class);
        Optional<Account> account = childMap.getChild(Account.class);

        Optional<Identity> owner = account
                .flatMap(a -> Optional.ofNullable(a.getOwner()))
                .flatMap(ownerId -> getByUcoId(mapping, ownerId, Identity.class));

        if (Stream.of(emailAddr, pathRel, windowsAcct, digitalAcct, account, owner).anyMatch(o -> !o.isPresent())) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> emailAttr = emailAddr.flatMap(e -> getAttr(TSK_EMAIL, e.getValue()));
        Optional<BlackboardAttribute> pathAttr = pathRel.flatMap(e -> getAttr(TSK_PATH, e.getPath()));
        Optional<BlackboardAttribute> groupsAttr = windowsAcct.flatMap(e -> getAttr(TSK_GROUPS, e.getGroups()));
        Optional<BlackboardAttribute> flagAttr = getAttr(TSK_FLAG, trace.getTag());
        Optional<BlackboardAttribute> displayNameAttr = digitalAcct.flatMap(da -> getAttr(TSK_DISPLAY_NAME, da.getDisplayName()));
        Optional<BlackboardAttribute> dateTimeAttr = digitalAcct.flatMap(da -> getAttr(TSK_DATETIME_ACCESSED, da.getLastLoginTime()));
        Optional<BlackboardAttribute> descriptionAttr = digitalAcct.flatMap(da -> getAttr(TSK_DESCRIPTION, da.getDescription()));
        Optional<BlackboardAttribute> nameAttr = owner.flatMap(o -> getAttr(TSK_NAME, o.getName()));

        Optional<BlackboardAttribute> accountTypeAttr = account.flatMap(a -> getAttr(TSK_ACCOUNT_TYPE, a.getAccountType()));
        Optional<BlackboardAttribute> userIdAttr = account.flatMap(a -> getAttr(TSK_USER_ID, a.getAccountIdentifier()));
        Optional<BlackboardAttribute> dateTimeCreatedAttr = account.flatMap(a -> getTimeStampAttr(TSK_DATETIME_CREATED, a.getCreatedTime()));

        return newArtifact(content, TSK_OS_ACCOUNT,
                getFiltered(emailAttr, pathAttr, groupsAttr, flagAttr, displayNameAttr, dateTimeAttr,
                        descriptionAttr, nameAttr, accountTypeAttr, userIdAttr, dateTimeAttr));
    }

    private Optional<BlackboardArtifact> importServiceAccount(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // this assumes ordering of output for digital accounts
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMap = getChildren(trace);

        Optional<Account> acct = childMap.getChild(Account.class);
        Optional<DomainName> domain = childMap.getChild(DomainName.class);

        Optional<EmailAddress> emailAddr = childMap.getChild(EmailMessage.class)
                .flatMap(message -> Optional.ofNullable(message.getInReplyTo()))
                .flatMap(replyToId -> getByUcoId(mapping, replyToId, Trace.class))
                .flatMap(t -> getChild(t, EmailAddress.class));

        Optional<AccountAuthentication> auth = childMap.getChild(AccountAuthentication.class);
        Optional<PathRelation> pathRel = childMap.getChild(PathRelation.class);
        Optional<URL> url = childMap.getChild(URL.class);

        Optional<ApplicationAccount> appAcct = childMap.getChild(ApplicationAccount.class);
        Optional<Application> application = appAcct
                .flatMap(a -> Optional.ofNullable(a.getApplication()))
                .flatMap(appId -> getByUcoId(mapping, appId, Application.class));

        List<DigitalAccount> digAccts = childMap.getChildren(DigitalAccount.class);

        if (Stream.of(acct, domain, emailAddr, auth, pathRel, url, appAcct, application).anyMatch(opt -> !opt.isPresent()) || digAccts.size() < 2) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> inReplyToAttr = emailAddr.flatMap(e -> getAttr(TSK_EMAIL_REPLYTO, e.getValue()));
        Optional<BlackboardAttribute> catAttr = acct.flatMap(a -> getAttr(TSK_CATEGORY, a.getAccountType()));
        Optional<BlackboardAttribute> domainAttr = domain.flatMap(d -> getAttr(TSK_DOMAIN, d.getValue()));
        Optional<BlackboardAttribute> passwordAttr = auth.flatMap(a -> getAttr(TSK_PASSWORD, a.getPassword()));
        Optional<BlackboardAttribute> pathAttr = pathRel.flatMap(a -> getAttr(TSK_PATH, a.getPath()));
        Optional<BlackboardAttribute> urlAttr = url.flatMap(a -> getAttr(TSK_URL, a.getFullValue()));
        Optional<BlackboardAttribute> descAttr = getAttr(TSK_DESCRIPTION, trace.getDescription());
        Optional<BlackboardAttribute> progNameAttr = application.flatMap(a -> getAttr(TSK_PROG_NAME, a.getApplicationIdentifier()));
        Optional<BlackboardAttribute> userIdAttr = acct.flatMap(a -> getAttr(TSK_USER_ID, a.getId()));
        Optional<BlackboardAttribute> timeCreatedAttr = acct.flatMap(a -> getTimeStampAttr(TSK_DATETIME_CREATED, a.getCreatedTime()));

        if (!progNameAttr.isPresent() || !userIdAttr.isPresent()) {
            return Optional.empty();
        }

        List<Facet> facets = trace.getHasPropertyBundle() == null ? Collections.emptyList() : trace.getHasPropertyBundle();
        Stream<BlackboardAttribute> digAcctAttrs = getFiltered(digAccts.stream()
                .map((digAcct) -> (facets.indexOf(digAcct) == 3)
                ? getAttr(TSK_NAME, digAcct.getDisplayName())
                : getAttr(TSK_USER_NAME, digAcct.getDisplayName())));

        Stream<BlackboardAttribute> remainingAttrs = getFiltered(Stream.of(
                inReplyToAttr, catAttr, domainAttr, passwordAttr, pathAttr, urlAttr,
                descAttr, progNameAttr, userIdAttr, timeCreatedAttr));

        return newArtifact(content, TSK_SERVICE_ACCOUNT,
                Stream.concat(digAcctAttrs, remainingAttrs).collect(Collectors.toList()));
    }

    private Optional<BlackboardArtifact> importContact(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        ChildMapping childMap = getChildren((Trace) ucoObject);

        Map<String, EmailAddress> emailAddresses = childMap.getChildren(EmailAddress.class).stream()
                .collect(Collectors.toMap(eMsg -> eMsg.getTag() == null ? "" : eMsg.getTag(), eMsg -> eMsg, (e1, e2) -> e1));

        Map<String, PhoneAccount> phoneAccounts = childMap.getChildren(PhoneAccount.class).stream()
                .collect(Collectors.toMap(phoneAcct -> phoneAcct.getTag() == null ? "" : phoneAcct.getTag(), phoneAcct -> phoneAcct, (p1, p2) -> p1));

        Optional<EmailAddress> email = Optional.ofNullable(emailAddresses.get(""));
        Optional<EmailAddress> homeEmail = Optional.ofNullable(emailAddresses.get("Home"));
        Optional<EmailAddress> workEmail = Optional.ofNullable(emailAddresses.get("Work"));

        Optional<PhoneAccount> phone = Optional.ofNullable(phoneAccounts.get(""));
        Optional<PhoneAccount> homePhone = Optional.ofNullable(phoneAccounts.get("Home"));
        Optional<PhoneAccount> workPhone = Optional.ofNullable(phoneAccounts.get("Work"));
        Optional<PhoneAccount> mobilePhone = Optional.ofNullable(phoneAccounts.get("Mobile"));

        Optional<URL> url = childMap.getChild(URL.class);

        Optional<Contact> contact = childMap.getChild(Contact.class);

        if (!email.isPresent() || !homeEmail.isPresent() || !workEmail.isPresent()
                || !phone.isPresent() || !homePhone.isPresent() || !workPhone.isPresent() || !mobilePhone.isPresent()
                || !url.isPresent() || !contact.isPresent()) {

            return Optional.empty();
        }

        Optional<BlackboardAttribute> emailAttr = email.flatMap(emsg -> getAttr(TSK_EMAIL, emsg.getValue()));
        Optional<BlackboardAttribute> homeEmailAttr = homeEmail.flatMap(emsg -> getAttr(TSK_EMAIL_HOME, emsg.getValue()));
        Optional<BlackboardAttribute> officeEmailAttr = workEmail.flatMap(emsg -> getAttr(TSK_EMAIL_OFFICE, emsg.getValue()));

        Optional<BlackboardAttribute> phoneAttr = phone.flatMap(p -> getAttr(TSK_PHONE_NUMBER, p.getPhoneNumber()));
        Optional<BlackboardAttribute> homePhoneAttr = homePhone.flatMap(p -> getAttr(TSK_PHONE_NUMBER_HOME, p.getPhoneNumber()));
        Optional<BlackboardAttribute> officePhoneAttr = workPhone.flatMap(p -> getAttr(TSK_PHONE_NUMBER_OFFICE, p.getPhoneNumber()));
        Optional<BlackboardAttribute> mobilePhoneAttr = mobilePhone.flatMap(p -> getAttr(TSK_PHONE_NUMBER_MOBILE, p.getPhoneNumber()));

        Optional<BlackboardAttribute> nameAttr = contact.flatMap(c -> getAttr(TSK_NAME, c.getContactName()));

        List<BlackboardAttribute> attrs = getFiltered(emailAttr, homeEmailAttr, officeEmailAttr, phoneAttr, homePhoneAttr, officePhoneAttr, mobilePhoneAttr, nameAttr);

        if (attrs.isEmpty()) {
            return Optional.empty();
        }

        url.flatMap(u -> getAttr(TSK_URL, u.getFullValue()))
                .ifPresent(attrs::add);

        return newArtifact(content, TSK_CONTACT, attrs);
    }

    private Optional<BlackboardArtifact> importMessage(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        ChildMapping childMapping = getChildren(trace);

        Optional<Message> message = childMapping.getChild(Message.class);

        Optional<org.sleuthkit.datamodel.Account.Type> messageTypeOpt = message
                .flatMap(msg -> Optional.ofNullable(msg.getApplication()))
                .flatMap(relatedId -> getByUcoId(mapping, relatedId, Trace.class))
                .flatMap(relatedTrace -> getChild(relatedTrace, Application.class))
                .flatMap(app -> Optional.ofNullable(app.getApplicationIdentifier()))
                .flatMap(accountTypeStr -> {
                    org.sleuthkit.datamodel.Account.Type accountType = sleuthkitCase.getCommunicationsManager().getAccountType(accountTypeStr);
                    if (accountType == null) {
                        accountType = sleuthkitCase.getCommunicationsManager().addAccountType(accountTypeStr, accountTypeStr);
                    }
                    return Optional.ofNullable(accountType);
                });

        Optional<String> textOpt = message.flatMap(msg -> Optional.ofNullable(msg.getMessageText()));

        if (!messageTypeOpt.isPresent() || !textOpt.isPresent()) {
            return Optional.empty();
        }

        org.sleuthkit.datamodel.Account.Type messageType = messageTypeOpt.get();
        String text = textOpt.get();

        Optional<EmailMessage> emailMessage = childMapping.getChild(EmailMessage.class);
        Optional<PhoneAccount> phoneAccount = childMapping.getChild(PhoneAccount.class);
        Optional<PhoneCall> phoneCall = childMapping.getChild(PhoneCall.class);
        Optional<SMSMessage> smsMessage = childMapping.getChild(SMSMessage.class);

        List<String> attachments = getFiltered(
                childMapping.getChildren(Attachment.class).stream()
                        .map(attach -> Optional.ofNullable(attach.getUrl())))
                .collect(Collectors.toList());

        Optional<Long> dateTime = message.flatMap(msg -> getEpochTime(msg.getSentTime()));
        Optional<String> direction = message.flatMap(msg -> Optional.ofNullable(msg.getMessageType()));
        Optional<String> threadId = message.flatMap(msg -> Optional.ofNullable(msg.getId()));
        Optional<String> phoneNumber = phoneAccount.flatMap(phoneAcct -> Optional.ofNullable(phoneAcct.getPhoneNumber()));

        MessageReadStatus readStatus = smsMessage
                .flatMap(sms -> Optional.ofNullable(sms.getIsRead()))
                .map(isRead -> isRead ? MessageReadStatus.READ : MessageReadStatus.UNREAD)
                .orElse(MessageReadStatus.UNKNOWN);

        Optional<String> emailFrom = emailMessage
                .flatMap(emsg -> Optional.ofNullable(emsg.getSender()))
                .flatMap(relatedId -> getByUcoId(mapping, relatedId, Trace.class))
                .flatMap(relatedTrace -> getChild(relatedTrace, EmailAddress.class))
                .flatMap(addr -> Optional.ofNullable(addr.getValue()));

        Optional<String> phoneFrom = phoneCall
                .flatMap(call -> Optional.ofNullable(call.getFrom()))
                .flatMap(relatedId -> getByUcoId(mapping, relatedId, Trace.class))
                .flatMap(relatedTrace -> getChild(relatedTrace, PhoneAccount.class))
                .flatMap(addr -> Optional.ofNullable(addr.getPhoneNumber()));

        Optional<String> phoneTo = phoneCall
                .flatMap(call -> Optional.ofNullable(call.getTo()))
                .flatMap(relatedId -> getByUcoId(mapping, relatedId, Trace.class))
                .flatMap(relatedTrace -> getChild(relatedTrace, PhoneAccount.class))
                .flatMap(addr -> Optional.ofNullable(addr.getPhoneNumber()));

        CommunicationArtifactsHelper helper = new CommunicationArtifactsHelper(sleuthkitCase, CASE_UCO_SOURCE, content, messageType);

        BlackboardArtifact artifact = helper.addMessage(messageType.getTypeName(), direction, sender, recipient,
                dateTime.orElse(0L), readStatus, subject, text, threadId.orElse(null),
                otherAttrs);

        return Optional.of(artifact);
    }

    private Optional<BlackboardArtifact> importMetadataExif(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<Device> device = getChild(trace, Device.class);
        Optional<LatLongCoordinates> coordinates = getChild(trace, LatLongCoordinates.class);

        if (!device.isPresent() || !coordinates.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> deviceMake = device.flatMap((dev) -> getAttr(TSK_DEVICE_MAKE, dev.getManufacturer()));
        Optional<BlackboardAttribute> deviceModel = device.flatMap((dev) -> getAttr(TSK_DEVICE_MODEL, dev.getModel()));

        Optional<BlackboardAttribute> latitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_LATITUDE, latLng.getLatitude()));
        Optional<BlackboardAttribute> longitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_LONGITUDE, latLng.getLongitude()));
        Optional<BlackboardAttribute> altitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_ALTITUDE, latLng.getAltitude()));

        Optional<BlackboardAttribute> createdTime = getTimeStampAttr(TSK_DATETIME_CREATED, trace.getCreatedTime());

        List<BlackboardAttribute> attrs = getFiltered(deviceMake, deviceModel, latitude, longitude, altitude, createdTime);

        return attrs.isEmpty()
                ? newArtifact(content, TSK_METADATA_EXIF, attrs)
                : Optional.empty();
    }

    private Optional<BlackboardArtifact> importCallLog(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<PhoneCall> phoneCall = getChild(trace, PhoneCall.class);

        Optional<BlackboardAttribute> phoneFrom = phoneCall
                .flatMap(call -> Optional.ofNullable(call.getFrom()))
                .flatMap(fromId -> getByUcoId(mapping, fromId, Trace.class))
                .flatMap(fromTrace -> getChild(fromTrace, PhoneAccount.class))
                .flatMap(phoneAcct -> getAttr(TSK_PHONE_NUMBER_FROM, phoneAcct.getPhoneNumber()));

        Optional<BlackboardAttribute> phoneTo = phoneCall
                .flatMap(call -> Optional.ofNullable(call.getTo()))
                .flatMap(toId -> getByUcoId(mapping, toId, Trace.class))
                .flatMap(toTrace -> getChild(toTrace, PhoneAccount.class))
                .flatMap(phoneAcct -> getAttr(TSK_PHONE_NUMBER_TO, phoneAcct.getPhoneNumber()));

        Optional<PhoneAccount> phoneAccount = getChild(trace, PhoneAccount.class);
        Optional<BlackboardAttribute> phoneNumber = phoneAccount
                .flatMap(phoneAcct -> getAttr(TSK_PHONE_NUMBER, phoneAcct.getPhoneNumber()));

        Optional<Contact> contact = getChild(trace, Contact.class);

        Optional<BlackboardAttribute> name = contact.flatMap(c -> getAttr(TSK_NAME, c.getContactName()));

        if (!phoneCall.isPresent() || !contact.isPresent() || !phoneAccount.isPresent()
                || getFiltered(phoneNumber, phoneFrom, phoneTo).isEmpty()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> endTime = phoneCall.flatMap(call -> getTimeStampAttr(TSK_DATETIME_END, call.getEndTime()));
        Optional<BlackboardAttribute> startTime = phoneCall.flatMap(call -> getTimeStampAttr(TSK_DATETIME_START, call.getStartTime()));
        Optional<BlackboardAttribute> direction = phoneCall.flatMap(call -> getAttr(TSK_DIRECTION, call.getCallType()));

        return newArtifact(content, TSK_CALLLOG, getFiltered(phoneFrom, phoneTo, phoneNumber, name, direction, startTime, endTime));
    }

    private Optional<BlackboardArtifact> importCalendarEntry(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<CalendarEntry> calEntry = getChild(trace, CalendarEntry.class);

        Optional<BlackboardAttribute> startTime = calEntry.flatMap(ce -> getTimeStampAttr(TSK_DATETIME_START, ce.getStartTime()));
        Optional<BlackboardAttribute> calType = calEntry.flatMap(ce -> getAttr(TSK_CALENDAR_ENTRY_TYPE, ce.getEventType()));

        if (!startTime.isPresent() || !calType.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> endTime = calEntry.flatMap(ce -> getTimeStampAttr(TSK_DATETIME_END, ce.getEndTime()));
        Optional<BlackboardAttribute> description = calEntry.flatMap(ce -> getAttr(TSK_DESCRIPTION, ce.getDescription()));

        Optional<BlackboardAttribute> location = calEntry
                .flatMap(ce -> Optional.ofNullable(ce.getLocation()))
                .flatMap(locId -> getByUcoId(mapping, locId, Location.class))
                .flatMap(loc -> getAttr(TSK_LOCATION, loc.getName()));

        return newArtifact(content, TSK_CALENDAR_ENTRY, getFiltered(startTime, calType, endTime, description, location));
    }

    private Optional<BlackboardArtifact> importSpeedDialEntry(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<Contact> contact = getChild(trace, Contact.class);
        Optional<BlackboardAttribute> phoneNumber = getChild(trace, PhoneAccount.class).flatMap(phoneAcct -> getAttr(TSK_PHONE_NUMBER, phoneAcct.getPhoneNumber()));

        if (!contact.isPresent() || !phoneNumber.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> namePerson = contact.flatMap(c -> getAttr(TSK_NAME_PERSON, c.getContactName()));

        return newArtifact(content, TSK_SPEED_DIAL_ENTRY, getFiltered(phoneNumber, namePerson));
    }

    private Optional<BlackboardArtifact> importBluetoothPairing(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<BlackboardAttribute> macAddress = getChild(trace, MACAddress.class)
                .flatMap(macAddr -> getAttr(TSK_MAC_ADDRESS, macAddr.getValue()));

        Optional<BlackboardAttribute> deviceName = getChild(trace, MobileDevice.class)
                .flatMap(mobileDevice -> getAttr(TSK_DEVICE_NAME, mobileDevice.getBluetoothDeviceName()));

        Optional<BlackboardAttribute> dateTime = getTimeStampAttr(TSK_DATETIME, trace.getCreatedTime());

        return deviceName.isPresent()
                ? newArtifact(content, TSK_BLUETOOTH_PAIRING, getFiltered(macAddress, deviceName, dateTime))
                : Optional.empty();
    }

    private Optional<BlackboardArtifact> importGpsBookmark(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // similar except for Application instance from gps search 

        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<BlackboardAttribute> createdTime = getTimeStampAttr(TSK_DATETIME, trace.getCreatedTime());

        Optional<LatLongCoordinates> coordinates = getChild(trace, LatLongCoordinates.class);

        Optional<BlackboardAttribute> latitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_LATITUDE, latLng.getLatitude()));
        Optional<BlackboardAttribute> longitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_LONGITUDE, latLng.getLongitude()));

        Optional<Application> application = getChild(trace, Application.class);

        if (!application.isPresent() || !latitude.isPresent() || !longitude.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> progName = application.flatMap((app) -> getAttr(TSK_PROG_NAME, app.getApplicationIdentifier()));

        Optional<BlackboardAttribute> altitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_ALTITUDE, latLng.getAltitude()));

        Optional<BlackboardAttribute> location = getChild(trace, SimpleAddress.class).flatMap((addr) -> getAttr(TSK_LOCATION, addr.getDescription()));

        Optional<BlackboardAttribute> name = getFirstPresent(
                getSourcesFromTarget(mapping, trace.getId(), Location.class).stream()
                        .map((loc) -> getAttr(TSK_NAME, loc.getName())));

        return newArtifact(content, TSK_GPS_BOOKMARK, getFiltered(createdTime, latitude, longitude, altitude, location, name));
    }

    private Optional<BlackboardArtifact> importGpsLastKnownLocation(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // indistinguishable from gps search 

        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<BlackboardAttribute> createdTime = getTimeStampAttr(TSK_DATETIME, trace.getCreatedTime());

        Optional<LatLongCoordinates> coordinates = getChild(trace, LatLongCoordinates.class);

        Optional<BlackboardAttribute> latitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_LATITUDE, latLng.getLatitude()));
        Optional<BlackboardAttribute> longitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_LONGITUDE, latLng.getLongitude()));

        if (!latitude.isPresent() || !longitude.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> altitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_ALTITUDE, latLng.getAltitude()));

        Optional<BlackboardAttribute> location = getChild(trace, SimpleAddress.class).flatMap((addr) -> getAttr(TSK_LOCATION, addr.getDescription()));

        Optional<BlackboardAttribute> name = getFirstPresent(
                getSourcesFromTarget(mapping, trace.getId(), Location.class).stream()
                        .map((loc) -> getAttr(TSK_NAME, loc.getName())));

        return newArtifact(content, TSK_GPS_LAST_KNOWN_LOCATION, getFiltered(createdTime, latitude, longitude, altitude, location, name));
    }

    private Optional<BlackboardArtifact> importGpsSearch(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<BlackboardAttribute> createdTime = getTimeStampAttr(TSK_DATETIME, trace.getCreatedTime());

        Optional<LatLongCoordinates> coordinates = getChild(trace, LatLongCoordinates.class);

        Optional<BlackboardAttribute> latitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_LATITUDE, latLng.getLatitude()));
        Optional<BlackboardAttribute> longitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_LONGITUDE, latLng.getLongitude()));

        if (!latitude.isPresent() || !longitude.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> altitude = coordinates.flatMap((latLng) -> getAttr(TSK_GEO_ALTITUDE, latLng.getAltitude()));

        Optional<BlackboardAttribute> location = getChild(trace, SimpleAddress.class).flatMap((addr) -> getAttr(TSK_LOCATION, addr.getDescription()));

        Optional<BlackboardAttribute> name = getFirstPresent(
                getSourcesFromTarget(mapping, trace.getId(), Location.class).stream()
                        .map((loc) -> getAttr(TSK_NAME, loc.getName())));

        return newArtifact(content, TSK_GPS_SEARCH, getFiltered(createdTime, latitude, longitude, altitude, location, name));
    }

    private Optional<BlackboardArtifact> importProgRun(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // this is likely ambiguous with other Application instances with prog name

        Optional<Application> application = getAs(ucoObject, Trace.class)
                .flatMap(trace -> getChild(trace, Application.class));

        Optional<BlackboardAttribute> progName = application
                .flatMap((app) -> getAttr(TSK_PROG_NAME, app.getApplicationIdentifier()));

        if (!progName.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> count = application
                .flatMap((app) -> getAttr(TSK_COUNT, app.getNumberOfLaunches()));

        return newArtifact(content, TSK_MESSAGE, getFiltered(progName, count));
    }

    private Optional<BlackboardArtifact> importEncryptionDetected(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // potentially ambiguous assertion

        Optional<BlackboardAttribute> comment = getAs(ucoObject, Assertion.class)
                .flatMap((asrtn) -> getAttr(TSK_COMMENT, asrtn.getStatement()));

        return comment.isPresent()
                ? newArtifact(content, TSK_ENCRYPTION_DETECTED, getFiltered(comment))
                : Optional.empty();
    }

    private Optional<BlackboardArtifact> importInterestingArtifact(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // assertion seems to be main 
        if (!(ucoObject instanceof Assertion)) {
            return Optional.empty();
        }

        Assertion assertion = (Assertion) ucoObject;
        Optional<BlackboardAttribute> setName = getAttr(TSK_SET_NAME, assertion.getName());
        Optional<BlackboardAttribute> comment = getAttr(TSK_COMMENT, assertion.getStatement());

        if (!setName.isPresent() || !comment.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> associatedArtifact = getFirstPresent(
                getTargetIdsFromSource(mapping, assertion.getId()).stream()
                        .map(id -> getTskObjByUcoId(mapping, id, BlackboardArtifact.class)
                        .flatMap(art -> getAttr(TSK_ASSOCIATED_ARTIFACT, art.getId()))));

        return newArtifact(content, TSK_INTERESTING_ARTIFACT_HIT, getFiltered(setName, comment, associatedArtifact));
    }

    private Optional<BlackboardArtifact> importGPSRoute(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // what are assumed children of this?  the assumption that an application and simple address are present is flimsy at best
        // application / simple address is used elsewhere and appears to be main identifying feature
        // no waypoints?

        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<Application> application = getChild(trace, Application.class);
        Optional<SimpleAddress> address = getChild(trace, SimpleAddress.class);

        if (!application.isPresent() || !address.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> progName = application
                .flatMap((app) -> getAttr(TSK_PROG_NAME, app.getApplicationIdentifier()));

        Optional<BlackboardAttribute> location = address
                .flatMap((addr) -> getAttr(TSK_LOCATION, addr.getDescription()));

        Optional<BlackboardAttribute> dateTime = getTimeStampAttr(TSK_DATETIME, trace.getCreatedTime());

        Optional<BlackboardAttribute> name = getFirstPresent(
                getSourcesFromTarget(mapping, trace.getId(), Location.class).stream()
                        .map(loc -> getAttr(TSK_NAME, loc.getName())));

        return newArtifact(content, TSK_GPS_ROUTE, getFiltered(progName, location, dateTime, name));
    }

    private Optional<BlackboardArtifact> importRemoteDrive(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // this may be ambiguous with the PathRelation
        // order is assumed for import

        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        List<PathRelation> pathRels = getChildren((Trace) ucoObject, PathRelation.class);

        if (pathRels.size() < 2) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> remotePath = getAttr(TSK_REMOTE_PATH, pathRels.get(0).getPath());

        if (!remotePath.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> localPath = getAttr(TSK_LOCAL_PATH, pathRels.get(1).getPath());

        return newArtifact(content, TSK_REMOTE_DRIVE, getFiltered(remotePath, localPath));
    }

    private Optional<BlackboardArtifact> importAccount(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // going through communications manager to create account
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        List<Account> accounts = getChildren(trace, Account.class);

        if (accounts.isEmpty()) {
            return Optional.empty();
        }

        Map<BlackboardAttribute.Type, String> attrMapping = new HashMap<>();
        for (Account account : accounts) {
            if (account.getAccountType() != null) {
                if (account.getName() != null) {
                    attrMapping.put(TSK_SET_NAME, account.getName());

                    if (account.getAccountIdentifier() != null) {
                        attrMapping.put(TSK_CARD_NUMBER, account.getAccountIdentifier());
                    }
                } else {
                    attrMapping.put(TSK_ACCOUNT_TYPE, account.getAccountType());

                    if (account.getAccountIdentifier() != null) {
                        attrMapping.put(TSK_ID, account.getAccountIdentifier());
                    }
                }
            }
        }

        CommunicationsManager commManager = this.sleuthkitCase.getCommunicationsManager();

        String accountTypeStr = attrMapping.remove(TSK_ACCOUNT_TYPE);
        if (accountTypeStr == null) {
            return Optional.empty();
        }

        org.sleuthkit.datamodel.Account.Type accountType = commManager.getAccountType(accountTypeStr);
        if (accountType == null) {
            accountType = commManager.addAccountType(accountTypeStr, accountTypeStr);
        }

        String tskId = attrMapping.get(TSK_CARD_NUMBER);
        if (tskId == null) {
            tskId = attrMapping.get(TSK_ID);
        }

        AccountFileInstance instance = commManager.createAccountFileInstance(accountType, tskId, CASE_UCO_SOURCE, content);

        Optional<BlackboardAttribute> setName = getAttr(TSK_SET_NAME, attrMapping.get(TSK_SET_NAME));
        if (setName.isPresent()) {
            instance.addAttribute(setName.get());
        }

        return instance;
    }

    private Optional<BlackboardArtifact> importEncryptionSuspected(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // potentially ambiguous assertion

        Optional<BlackboardAttribute> comment = getAs(ucoObject, Assertion.class)
                .flatMap((asrtn) -> getAttr(TSK_COMMENT, asrtn.getStatement()));

        return comment.isPresent()
                ? newArtifact(content, TSK_ENCRYPTION_SUSPECTED, getFiltered(comment))
                : Optional.empty();
    }

    private Optional<BlackboardArtifact> importObjectDetected(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // potentially ambiguous assertion

        Optional<Assertion> assertion = getAs(ucoObject, Assertion.class);

        Optional<BlackboardAttribute> comment = assertion.flatMap((asrtn) -> getAttr(TSK_COMMENT, asrtn.getStatement()));

        if (!comment.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> description = assertion.flatMap((asrtn) -> getAttr(TSK_DESCRIPTION, asrtn.getDescription()));

        return newArtifact(content, TSK_OBJECT_DETECTED, getFiltered(comment, description));
    }

    private static final Pattern BLANK_NODE_REGEX = Pattern.compile("_:(.*)");

    private Optional<BlackboardArtifact> importWifiNetwork(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<WirelessNetworkConnection> connectionOpt = getChild(trace, WirelessNetworkConnection.class);

        Optional<BlackboardAttribute> ssid = connectionOpt
                .flatMap(conn -> getAttr(TSK_SSID, conn.getSsid()));

        if (!ssid.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> dateTime = connectionOpt
                .flatMap(conn -> getTimeStampAttr(TSK_DATETIME, conn.getCreatedTime()));

        Optional<BlackboardAttribute> deviceId = connectionOpt
                .flatMap(conn -> Optional.ofNullable(conn.getId()))
                .flatMap((idNodeVal) -> {
                    String idStr = null;

                    Matcher matcher = BLANK_NODE_REGEX.matcher(idNodeVal);
                    if (matcher.find()) {
                        idStr = matcher.group(1);
                    }

                    return Optional.ofNullable(idStr);
                })
                .flatMap((idStr) -> getAttr(TSK_DEVICE_ID, idStr));

        return newArtifact(content, TSK_WIFI_NETWORK, getFiltered(ssid, dateTime, deviceId));
    }

    private Optional<BlackboardArtifact> importDeviceInfo(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<BlackboardAttribute> imei = getChild(trace, MobileDevice.class)
                .flatMap((mobileDev) -> getAttr(TSK_IMEI, mobileDev.getIMEI()));

        Optional<SIMCard> simCard = getChild(trace, SIMCard.class);

        Optional<BlackboardAttribute> iccid = simCard
                .flatMap((sCard) -> getAttr(TSK_ICCID, sCard.getICCID()));

        Optional<BlackboardAttribute> imsi = simCard
                .flatMap((sCard) -> getAttr(TSK_IMSI, sCard.getIMSI()));

        List<BlackboardAttribute> attrs = getFiltered(imei, iccid, imsi);

        return attrs.isEmpty()
                ? Optional.empty()
                : newArtifact(content, TSK_DEVICE_INFO, attrs);
    }

    private Optional<BlackboardArtifact> importSimAttached(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // get ucoObject as trace
        Optional<SIMCard> simCardOpt = getAs(ucoObject, Trace.class)
                // find child SIMCard if exists
                .flatMap(trace -> getChild(trace, SIMCard.class));

        if (!simCardOpt.isPresent()) {
            return Optional.empty();
        }

        SIMCard simCard = simCardOpt.get();
        List<BlackboardAttribute> attrs = getFiltered(getAttr(TSK_ICCID, simCard.getICCID()), getAttr(TSK_IMSI, simCard.getIMSI()));

        return attrs.isEmpty()
                ? Optional.empty()
                : newArtifact(content, TSK_SIM_ATTACHED, attrs);
    }

    private Optional<BlackboardArtifact> importBluetoothAdapter(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // this is ambiguous with wifi network adapter    

        // get ucoObject as trace
        Optional<BlackboardAttribute> macAddress = getAs(ucoObject, Trace.class)
                // find child MACAddress if exists
                .flatMap(trace -> getChild(trace, MACAddress.class))
                // turn into tsk attribute if exists
                .flatMap(macAddr -> getAttr(TSK_MAC_ADDRESS, macAddr.getValue()));

        return macAddress.isPresent()
                ? newArtifact(content, TSK_BLUETOOTH_ADAPTER, Arrays.asList(macAddress.get()))
                : Optional.empty();
    }

    private Optional<BlackboardArtifact> importWifiNetworkAdapter(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {

        // get ucoObject as trace
        Optional<BlackboardAttribute> macAddress = getAs(ucoObject, Trace.class)
                // find child MACAddress if exists
                .flatMap(trace -> getChild(trace, MACAddress.class))
                // turn into tsk attribute if exists
                .flatMap(macAddr -> getAttr(TSK_MAC_ADDRESS, macAddr.getValue()));

        return macAddress.isPresent()
                ? newArtifact(content, TSK_WIFI_NETWORK_ADAPTER, Arrays.asList(macAddress.get()))
                : Optional.empty();
    }

    private Optional<BlackboardArtifact> importVerificationFailed(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // this will be ambiguous with other assertion instances

        Optional<BlackboardAttribute> comment = getAs(ucoObject, Assertion.class)
                .flatMap(assertion -> getAttr(TSK_COMMENT, assertion.getStatement()));

        return comment.isPresent()
                ? newArtifact(content, TSK_VERIFICATION_FAILED, getFiltered(comment))
                : Optional.empty();
    }

    private Optional<BlackboardArtifact> importDataSourceUsage(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // this is ambiguous since it is only a trace with a description

        Optional<BlackboardAttribute> description = getAs(ucoObject, Trace.class)
                .flatMap(trace -> getAttr(TSK_DESCRIPTION, trace.getDescription()));

        return description.isPresent()
                ? newArtifact(content, TSK_DATA_SOURCE_USAGE, getFiltered(description))
                : Optional.empty();
    }

    private Optional<BlackboardArtifact> importWebFormAddress(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // no TSK_COMMENT?  could be inserted
        // no TSK_COUNT

        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        Optional<BlackboardAttribute> location = getChild(trace, SimpleAddress.class)
                .flatMap(simpleAddr -> getAttr(TSK_LOCATION, simpleAddr.getDescription()));

        if (!location.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> email = getChild(trace, EmailAddress.class)
                .flatMap(emailAddr -> getAttr(TSK_EMAIL, emailAddr.getValue()));

        Optional<BlackboardAttribute> phoneAcct = getChild(trace, PhoneAccount.class)
                .flatMap(pa -> getAttr(TSK_PHONE_NUMBER, pa.getPhoneNumber()));

        Optional<BlackboardAttribute> accessedTime = getTimeStampAttr(TSK_DATETIME_ACCESSED, trace.getCreatedTime());
        Optional<BlackboardAttribute> modifiedTime = getTimeStampAttr(TSK_DATETIME_MODIFIED, trace.getModifiedTime());

        Optional<BlackboardAttribute> person = getFirstPresent(
                getSourcesFromTarget(mapping, trace.getId(), Person.class).stream()
                        .map(p -> getAttr(TSK_NAME_PERSON, p.getName())));

        return newArtifact(content, TSK_WEB_FORM_ADDRESS, getFiltered(email, phoneAcct, accessedTime, modifiedTime, person));
    }

    private Optional<BlackboardArtifact> importWebCache(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // does not appear that TSK_PATH_ID / TSK_DOMAIN are determined here
        // TSK_DOMAIN could be calculated

        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        Optional<BlackboardAttribute> pathRelation = getChild(trace, PathRelation.class)
                .flatMap(pathRel -> getAttr(TSK_PATH, pathRel.getPath()));

        Optional<BlackboardAttribute> url = getChild(trace, URL.class)
                .flatMap(u -> getAttr(TSK_URL, u.getFullValue()));

        if (!pathRelation.isPresent() || !url.isPresent()) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> headers = getChild(trace, HTTPConnection.class)
                .flatMap(httpCon -> getAttr(TSK_HEADERS, httpCon.getHttpRequestHeader()));

        Optional<BlackboardAttribute> createdTime = getAttr(TSK_DATETIME_CREATED, trace.getCreatedTime());

        return newArtifact(content, TSK_WEB_CACHE, getFiltered(pathRelation, url, headers, createdTime));
    }

    private Optional<BlackboardArtifact> importTimelineEvent(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Action)) {
            return Optional.empty();
        }

        Action action = (Action) ucoObject;

        Optional<BlackboardAttribute> dateTime = getTimeStampAttr(TSK_DATETIME, action.getStartTime());
        Optional<BlackboardAttribute> description = getAttr(TSK_DESCRIPTION, action.getDescription());
        Optional<BlackboardAttribute> tlType = getFirstPresent(
                getSourcesFromTarget(mapping, action.getId(), Trace.class).stream()
                        // find a related ActionArgument in the related traces
                        .flatMap(trace -> getChildren(trace, ActionArgument.class).stream())
                        // if one exists, create a TSK_TL_EVENT_TYPE by going from getArgumentName to an event type with that 
                        // display name to an attribute with the id of that event type
                        .map(actionArgument -> {
                            return Optional.ofNullable(actionArgument.getArgumentName())
                                    .flatMap(displayName -> Optional.ofNullable(eventTypeMapping.get(displayName)))
                                    .flatMap(evtType -> getAttr(TSK_TL_EVENT_TYPE, evtType.getTypeID()));
                        }));

        return newArtifact(content, TSK_TL_EVENT, getFiltered(dateTime, description, tlType));
    }

    private Optional<BlackboardArtifact> importClipboardContent(Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> tskText = getChild((Trace) ucoObject, Note.class)
                .flatMap(nt -> getAttr(TSK_TEXT, nt.getText()));

        if (!tskText.isPresent()) {
            return Optional.empty();
        }

        return newArtifact(content, TSK_CLIPBOARD_CONTENT, Arrays.asList(tskText.get()));
    }

    private Optional<BlackboardArtifact> importAssociatedObject(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        // this is risky, because we are looking for an empty trace
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        List<Facet> facets = ((Trace) ucoObject).getHasPropertyBundle();
        if (facets != null && facets.size() > 0) {
            return Optional.empty();
        }

        List<String> relatedArtifacts = getTargetIdsFromSource(mapping, ucoObject.getId());

        // NOTE: this assumes one and only one target for this source
        if (relatedArtifacts.size() != 1) {
            return Optional.empty();
        }

        Optional<BlackboardAttribute> attr = getTskObjByUcoId(mapping, relatedArtifacts.get(0), BlackboardArtifact.class)
                .flatMap((art) -> getAttr(TSK_ASSOCIATED_ARTIFACT, art.getId()));

        if (!attr.isPresent()) {
            return Optional.empty();
        }

        return newArtifact(content, TSK_ASSOCIATED_OBJECT, Arrays.asList(attr.get()));
    }

    private Optional<BlackboardArtifact> importUserContentSuspected(Content content, UcoObject ucoObject) throws TskCoreException {
        Optional<BlackboardAttribute> comment = getAs(ucoObject, Assertion.class)
                .flatMap(assertion -> getAttr(TSK_COMMENT, assertion.getStatement()));

        return comment.isPresent()
                ? newArtifact(content, TSK_USER_CONTENT_SUSPECTED, getFiltered(comment))
                : Optional.empty();
    }

    private Optional<BlackboardArtifact> importMetadata(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;
        Optional<Application> applicationOpt = getChild(trace, Application.class);
        List<ContentData> contentDataList = getChildren(trace, ContentData.class);

        if (contentDataList.size() < 1 || !applicationOpt.isPresent()) {
            return Optional.empty();
        }

        Application application = applicationOpt.get();

        Map<BlackboardAttribute.Type, BlackboardAttribute> attributes = new HashMap<>();

        getAttr(TSK_PROG_NAME, application.getApplicationIdentifier())
                .ifPresent((attr) -> attributes.put(attr.getAttributeType(), attr));

        getAttr(TSK_VERSION, application.getVersion())
                .ifPresent((attr) -> attributes.put(attr.getAttributeType(), attr));

        for (ContentData contentData : contentDataList) {
            getTimeStampAttr(TSK_DATETIME_CREATED, contentData.getCreatedTime())
                    .ifPresent((attr) -> attributes.put(attr.getAttributeType(), attr));

            getTimeStampAttr(TSK_DATETIME_MODIFIED, contentData.getModifiedTime())
                    .ifPresent((attr) -> attributes.put(attr.getAttributeType(), attr));

            getAttr(TSK_DESCRIPTION, contentData.getDescription())
                    .ifPresent((attr) -> attributes.put(attr.getAttributeType(), attr));

            // get owner by looking up related owner object from owner id in content data
            Optional.ofNullable(contentData.getOwner())
                    .flatMap(ownerId -> getByUcoId(mapping, ownerId, Identity.class))
                    .flatMap(ownerObj -> getAttr(TSK_OWNER, ownerObj.getName()))
                    .ifPresent((attr) -> attributes.put(attr.getAttributeType(), attr));

            if ("Last Printed".equalsIgnoreCase(contentData.getTag())) {
                getTimeStampAttr(TSK_LAST_PRINTED_DATETIME, contentData.getModifiedTime())
                        .ifPresent((attr) -> attributes.put(attr.getAttributeType(), attr));
            }
        }

        getFirstPresent(
                getSourcesFromTarget(mapping, trace.getId(), Identity.class).stream()
                        .filter(author -> "Last Author".equalsIgnoreCase(author.getTag()))
                        .map(author -> getAttr(TSK_USER_ID, author.getName())))
                .ifPresent((attr) -> attributes.put(attr.getAttributeType(), attr));

        getFirstPresent(
                getSourcesFromTarget(mapping, trace.getId(), Organization.class).stream()
                        .map(organization -> getAttr(TSK_ORGANIZATION, organization.getName())))
                .ifPresent((attr) -> attributes.put(attr.getAttributeType(), attr));

        return newArtifact(content, TSK_METADATA, new ArrayList<>(attributes.values()));
    }

    private Optional<BlackboardArtifact> newArtifact(Content content, BlackboardArtifact.Type type, List<BlackboardAttribute> attrs) throws TskCoreException {
        switch (type.getCategory()) {
            case DATA_ARTIFACT:
                return Optional.of(content.newDataArtifact(type, attrs));
            case ANALYSIS_RESULT:
                return Optional.of(content.newAnalysisResult(type, Score.SCORE_UNKNOWN, null, null, null, attrs).getAnalysisResult());
            default:
                return Optional.empty();
        }
    }

    private Optional<BlackboardArtifact> importGpsTrack(Content content, UcoObject ucoObject) throws TskCoreException {
        // name for latLng in export
        // created time for track point?
        // in GeoTrackPoints.TrackPoint: no velocity, distanceFromHomePoint, distanceTraveled

        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }

        Trace trace = (Trace) ucoObject;

        String exportName = trace.getName();
        List<LatLongCoordinates> coordinates = getChildren(trace, LatLongCoordinates.class);
        Optional<Application> application = getChild(trace, Application.class);

        if (coordinates.size() < 1 || !application.isPresent()) {
            return Optional.empty();
        }

        GeoTrackPoints points = new GeoTrackPoints();

        coordinates.stream()
                .map(latLng -> new GeoTrackPoints.TrackPoint(latLng.getLatitude(), latLng.getLongitude(), latLng.getAltitude(),
                latLng.getName(), null, null, null, getEpochTime(latLng.getCreatedTime()).orElse(null)))
                .forEach(points::addPoint);

        return Optional.of(content.newDataArtifact(TSK_GPS_TRACK,
                getFiltered(
                        getAttr(TSK_NAME, exportName),
                        getAttr(TSK_PROG_NAME, application.map(Application::getApplicationIdentifier).orElse(null)),
                        getJsonAttr(TSK_GEO_TRACKPOINTS, points)
                )));
    }

    private Optional<BlackboardArtifact> importExtractedText(Content content, Trace trace) throws TskCoreException {
        Optional<ExtractedString> extractedString = getChild(trace, ExtractedString.class);

        if (extractedString.isPresent()) {
            return Optional.of(content.newDataArtifact(TSK_KEYWORD_HIT,
                    getFiltered(getAttr(TSK_TEXT, extractedString.get().getStringValue()))));
        } else {
            return Optional.empty();
        }

    }

    private Optional<Content> getParent(IdMapping idMapping, Trace trace) {

    }

    private List<Content> getContent(Trace trace, IdMapping idMap) {
        Optional<Relationship> relationship = trace.getHasPropertyBundle().stream()
                .filter((facet) -> facet instanceof Relationship)
                .map((facet) -> (Relationship) facet)
                .filter((relationship) -> relationship.getSource() != null
                && relationship.getTarget() != null
                && CONTAINED_WITHIN_RELATIONSHIP.equalsIgnoreCase(relationship.getKindOfRelationship())
                && relationship.getIsDirectional())
                .findFirst();

        if (Boolean.valueOf(parentChildProperty)) {
            addToOutput(new BlankRelationshipNode()
                    .setSource(sourceId)
                    .setTarget(parentId)
                    .setKindOfRelationship("contained-within")
                    .isDirectional(true), output);
        }
    }

    private List<String> getTargetIdsFromSource(IdMapping idMap, String id) {

    }

    private <T extends UcoObject> List<T> getSourcesFromTarget(IdMapping idMap, String id, Class<T> clazz) {

    }

    private <T extends UcoObject> Optional<T> getByUcoId(IdMapping idMap, String id, Class<T> clazz) {

    }

    private <T extends Content> Optional<T> getTskObjByUcoId(IdMapping idMap, String id, Class<T> clazz) {

    }

    private <T> Optional<T> getAs(Object obj, Class<T> clazz) {
        return Optional.ofNullable((clazz.isInstance(obj) ? (T) obj : null));
    }

    private <T> Stream<T> getFiltered(Stream<Optional<T>> optionalStream) {
        return optionalStream
                .filter(Optional::isPresent)
                .map(Optional::get);
    }

    private <T> Optional<T> getFirstPresent(Stream<Optional<T>> optionalStream) {
        return getFiltered(optionalStream)
                .findFirst();
    }

    private <T> List<T> getFiltered(Optional<T>... items) {
        return getFiltered(Stream.of(items))
                .collect(Collectors.toList());
    }

    private <T> List<T> getFiltered(List<Optional<T>> items) {
        return getFiltered(items.stream())
                .collect(Collectors.toList());
    }

    private static class ChildMapping {

        private final Map<Class<? extends Facet>, List<Facet>> mapping;

        ChildMapping(List<Facet> facets) {
            Stream<? extends Facet> objStream = (facets != null) ? facets.stream() : Stream.empty();
            this.mapping = objStream.collect(Collectors.groupingBy(obj -> obj.getClass()));
        }

        <T extends UcoObject> Optional<T> getChild(Class<T> clazz) {
            List<Facet> objs = mapping.get(clazz);
            if (objs == null) {
                return Optional.empty();
            }

            return objs.stream().map(f -> (T) f).findFirst();
        }

        <T extends UcoObject> List<T> getChildren(Class<T> clazz) {
            List<Facet> objs = mapping.get(clazz);
            if (objs == null) {
                return Collections.emptyList();
            }

            return UnmodifiableList.of((List<T>) (List<?>) objs);
        }
    }

    private ChildMapping getChildren(Trace parentTrace) {
        return new ChildMapping(parentTrace.getHasPropertyBundle());
    }

    private <T extends Facet> List<T> getChildren(Trace parentTrace, Class<T> clazz) {
        return parentTrace.getHasPropertyBundle().stream()
                .filter((facet) -> clazz.isInstance(facet))
                .map((facet) -> (T) facet)
                .collect(Collectors.toList());
    }

    private <T extends Facet> Optional<T> getChild(Trace parentTrace, Class<T> clazz) {
        return parentTrace.getHasPropertyBundle().stream()
                .filter((facet) -> clazz.isInstance(facet))
                .map((facet) -> (T) facet)
                .findFirst();
    }

    private Optional<BlackboardAttribute> getTimeStampAttr(BlackboardAttribute.Type type, String value) {
        return getEpochTime(value)
                .flatMap((epochTime) -> getAttr(type, epochTime));
    }

    private Optional<BlackboardAttribute> getAttr(BlackboardAttribute.Type type, Double value) {
        return Optional.ofNullable(value)
                .map(timeVal -> new BlackboardAttribute(type, CASE_UCO_SOURCE, timeVal));
    }

    private Optional<BlackboardAttribute> getAttr(BlackboardAttribute.Type type, Long value) {
        return Optional.ofNullable(value)
                .map(timeVal -> new BlackboardAttribute(type, CASE_UCO_SOURCE, timeVal));
    }

    private Optional<BlackboardAttribute> getAttr(BlackboardAttribute.Type type, Integer value) {
        return Optional.ofNullable(value)
                .map(timeVal -> new BlackboardAttribute(type, CASE_UCO_SOURCE, timeVal));
    }

    private Optional<BlackboardAttribute> getAttr(BlackboardAttribute.Type type, String value) {
        return Optional.ofNullable(value)
                .map(val -> new BlackboardAttribute(type, CASE_UCO_SOURCE, val));
    }

    private Optional<BlackboardAttribute> getJsonAttr(BlackboardAttribute.Type type, Object attrVal) {
        return Optional.ofNullable(attrVal)
                .map(val -> BlackboardJsonAttrUtil.toAttribute(type, CASE_UCO_SOURCE, attrVal));
    }

    private Optional<Long> getEpochTime(String timeStamp) {
        if (timeStamp == null) {
            return Optional.empty();
        }

        try {
            return Optional.of(OffsetDateTime.parse(timeStamp).toEpochSecond());
        } catch (DateTimeParseException ex) {
            logger.log(Level.WARNING, "Unable to parse timestamp: " + timeStamp);
            return Optional.empty();
        }
    }

    /**
     * Add the parent-child relationship, if configured to do so.
     */
    private void addParentChildRelationship(List<JsonElement> output, String sourceId, String parentId) {
        String parentChildProperty = this.props.getProperty(INCLUDE_PARENT_CHILD_RELATIONSHIPS_PROP,
                DEFAULT_PARENT_CHILD_RELATIONSHIPS_VALUE);

        if (Boolean.valueOf(parentChildProperty)) {
            addToOutput(new BlankRelationshipNode()
                    .setSource(sourceId)
                    .setTarget(parentId)
                    .setKindOfRelationship("contained-within")
                    .isDirectional(true), output);
        }
    }
}
