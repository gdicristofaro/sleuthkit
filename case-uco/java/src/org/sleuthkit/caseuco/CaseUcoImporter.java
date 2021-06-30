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
import java.util.Collection;
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
import static org.sleuthkit.datamodel.BlackboardArtifact.ARTIFACT_TYPE.TSK_OS_ACCOUNT;
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
import org.sleuthkit.datamodel.AnalysisResult;
import org.sleuthkit.datamodel.BlackboardArtifact;
import static org.sleuthkit.datamodel.BlackboardArtifact.Type.TSK_KEYWORD_HIT;
import org.sleuthkit.datamodel.BlackboardAttribute;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_ACCOUNT_TYPE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_ASSOCIATED_ARTIFACT;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_CARD_NUMBER;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_COMMENT;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_COUNT;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME_ACCESSED;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME_CREATED;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DATETIME_MODIFIED;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DESCRIPTION;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_DEVICE_ID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_EMAIL;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_GEO_TRACKPOINTS;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_HEADERS;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_ICCID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_ID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_IMEI;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_IMSI;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_LAST_PRINTED_DATETIME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_LOCAL_PATH;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_LOCATION;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_MAC_ADDRESS;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_NAME_PERSON;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_ORGANIZATION;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_OWNER;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PATH;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PHONE_NUMBER;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_PROG_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_REMOTE_PATH;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_SET_NAME;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_SSID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_TL_EVENT_TYPE;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_URL;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_USER_ID;
import static org.sleuthkit.datamodel.BlackboardAttribute.Type.TSK_VERSION;
import org.sleuthkit.datamodel.CommunicationsManager;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.DataArtifact;
import org.sleuthkit.datamodel.Score;
import org.sleuthkit.datamodel.TimelineEventType;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.attributes.BlackboardJsonAttrUtil;
import org.sleuthkit.datamodel.blackboardutils.attributes.GeoTrackPoints;
import org.sleuthkit.datamodel.blackboardutils.attributes.MessageAttachments;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskData.DbType;
import sun.util.logging.PlatformLogger;

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
    
    private static final String INCLUDE_PARENT_CHILD_RELATIONSHIPS_PROP = "exporter.relationships.includeParentChild";
    private static final String DEFAULT_PARENT_CHILD_RELATIONSHIPS_VALUE = "true";
    private static final String CASE_UCO_SOURCE = "Case Uco Importer";
    private static final String CONTAINED_WITHIN_RELATIONSHIP = "contained-within";
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
    
    private void assembleWebCookie(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new URL()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new ContentData()
                        .setDataPayload(getValueIfPresent(artifact, StandardAttributeTypes.TSK_VALUE)));
        
        Trace cookieDomainNode = new BlankTraceNode()
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)));
        
        Trace applicationNode = new BlankTraceNode()
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        
        BrowserCookie cookie = new BrowserCookie()
                .setCookieName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME))
                .setCookieDomain(cookieDomainNode)
                .setApplication(applicationNode)
                .setAccessedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_START))
                .setExpirationTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_END));
        cookie.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        
        export.addBundle(cookie);
        
        addToOutput(export, output);
        addToOutput(cookieDomainNode, output);
        addToOutput(applicationNode, output);
    }
    
    private void assembleWebBookmark(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace applicationNode = new BlankTraceNode()
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        
        BrowserBookmark bookmark = new BrowserBookmark()
                .setUrlTargeted(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL))
                .setApplication(applicationNode);
        bookmark.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));
        bookmark.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        
        Trace export = new Trace(uuid)
                .addBundle(bookmark)
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)));
        
        addToOutput(export, output);
        addToOutput(applicationNode, output);
    }
    
    private void assembleGenInfo(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Hash hash = new Hash(uuid, getValueIfPresent(artifact, StandardAttributeTypes.TSK_HASH_PHOTODNA));
        addToOutput(hash, output);
    }
    
    private void assembleWebHistory(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace userNameNode = new BlankTraceNode();
        
        IdentityFacet identityFacet = new IdentityFacet();
        identityFacet.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_NAME));
        userNameNode.addBundle(identityFacet);
        
        Trace export = new Trace(uuid)
                .addBundle(new URL()
                        .setUserName(userNameNode)
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        
        addToOutput(export, output);
        addToOutput(userNameNode, output);
    }
    
    private void assembleWebDownload(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new URL()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addBundle(new File()
                        .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        addToOutput(export, output);
    }
    
    private void assembleDeviceAttached(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Device()
                        .setManufacturer(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MAKE))
                        .setModel(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MODEL))
                        .setId(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_ID)))
                .addBundle(new MACAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MAC_ADDRESS)));
        
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        addToOutput(export, output);
    }
    
    private void assembleHashsetHit(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SET_NAME));
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));
        
        addToOutput(export, output);
    }
    
    private void assembleInstalledProg(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new File()
                        .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH_SOURCE)));
        Software software = new Software();
        software.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME));
        export.addBundle(software);
        
        File file = new File()
                .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH));
        file.setModifiedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        
        file.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        export.addBundle(file);
        
        addToOutput(export, output);
    }
    
    private void assembleRecentObject(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        
        WindowsRegistryValue registryValue = new WindowsRegistryValue()
                .setData(getValueIfPresent(artifact, StandardAttributeTypes.TSK_VALUE));
        registryValue.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));
        
        export.addBundle(registryValue);
        
        File file = new File()
                .setAccessedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_ACCESSED));
        file.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        
        export.addBundle(file);
        
        addToOutput(export, output);
        
        Assertion assertion = new BlankAssertionNode()
                .setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));
        addToOutput(assertion, output);
        addToOutput(new BlankRelationshipNode()
                .setSource(assertion.getId())
                .setTarget(uuid), output);
    }
    
    private void assembleInterestingFileHit(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Assertion export = new Assertion(uuid);
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SET_NAME));
        export.setStatement(getValueIfPresent(artifact, StandardAttributeTypes.TSK_COMMENT));
        addToOutput(export, output);
    }
    
    private void assembleEmailMessage(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace bccNode = new BlankTraceNode()
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_BCC)));
        
        Trace ccNode = new BlankTraceNode()
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_CC)));
        
        Trace fromNode = new BlankTraceNode()
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_FROM)));
        
        Trace headerRawNode = new BlankTraceNode()
                .addBundle(new ExtractedString()
                        .setStringValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_HEADERS)));
        
        EmailMessage emailMessage = new EmailMessage();
        String html = getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_CONTENT_HTML);
        String plain = getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_CONTENT_PLAIN);
        String rtf = getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_CONTENT_RTF);
        
        if (html != null) {
            emailMessage.setBody(html);
            emailMessage.setContentType("text/html");
        } else if (rtf != null) {
            emailMessage.setBody(rtf);
            emailMessage.setContentType("text/rtf");
        } else if (plain != null) {
            emailMessage.setBody(plain);
            emailMessage.setContentType("text/plain");
        }
        
        Trace export = new Trace(uuid)
                .addBundle(emailMessage
                        .setReceivedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_RCVD))
                        .setSentTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_SENT))
                        .setBcc(bccNode)
                        .setCc(ccNode)
                        .setFrom(fromNode)
                        .setHeaderRaw(headerRawNode)
                        .setMessageID(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MSG_ID))
                        .setSubject(getValueIfPresent(artifact, StandardAttributeTypes.TSK_SUBJECT)))
                .addBundle(new File()
                        .setFilePath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)));
        
        addToOutput(export, output);
        addToOutput(bccNode, output);
        addToOutput(ccNode, output);
        addToOutput(fromNode, output);
        addToOutput(headerRawNode, output);
    }
    
    private void assembleWebSearchQuery(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace applicationNode = new BlankTraceNode()
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        
        Trace export = new Trace(uuid)
                .addBundle(new Note()
                        .setText(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEXT)))
                .addBundle(new Domain()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addBundle(new ApplicationAccount()
                        .setApplication(applicationNode));
        addToOutput(export, output);
        addToOutput(applicationNode, output);
    }
    
    private void assembleOsInfo(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Identity registeredOwnerNode = new BlankIdentityNode();
        registeredOwnerNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_OWNER));
        Identity registeredOrganizationNode = new BlankIdentityNode();
        registeredOrganizationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ORGANIZATION));
        
        OperatingSystem operatingSystem = new OperatingSystem()
                .setInstallDate(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME))
                .setVersion(getValueIfPresent(artifact, StandardAttributeTypes.TSK_VERSION));
        operatingSystem.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME));
        
        EnvironmentVariable envVar = new EnvironmentVariable()
                .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEMP_DIR));
        envVar.setName("TEMP");
        Trace tempDirectoryNode = new BlankTraceNode()
                .addBundle(envVar);
        
        Trace export = new Trace(uuid)
                .addBundle(operatingSystem)
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addBundle(new Device()
                        .setSerialNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PRODUCT_ID)))
                .addBundle(new ComputerSpecification()
                        .setHostName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME))
                        .setProcessorArchitecture(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROCESSOR_ARCHITECTURE)))
                .addBundle(new WindowsComputerSpecification()
                        .setRegisteredOrganization(registeredOrganizationNode)
                        .setRegisteredOwner(registeredOwnerNode)
                        .setWindowsTempDirectory(tempDirectoryNode));
        
        addToOutput(export, output);
        addToOutput(registeredOwnerNode, output);
        addToOutput(registeredOrganizationNode, output);
        addToOutput(tempDirectoryNode, output);
    }
    
    private void assembleOsAccount(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL)))
                .addBundle(new PathRelation()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addBundle(new WindowsAccount()
                        .setGroups(getValueIfPresent(artifact, StandardAttributeTypes.TSK_GROUPS)));
        
        export.setTag(getValueIfPresent(artifact, StandardAttributeTypes.TSK_FLAG));
        
        DigitalAccount digitalAccount = new DigitalAccount()
                .setDisplayName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DISPLAY_NAME))
                .setLastLoginTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_ACCESSED));
        digitalAccount.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));
        
        export.addBundle(digitalAccount);
        
        Identity ownerNode = new BlankIdentityNode();
        ownerNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));
        
        Account account = new Account()
                .setAccountType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_ACCOUNT_TYPE))
                .setOwner(ownerNode)
                .setAccountIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_ID));
        account.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        
        export.addBundle(account);
        
        addToOutput(export, output);
        addToOutput(ownerNode, output);
    }
    
    private void assembleServiceAccount(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace inReplyToNode = new BlankTraceNode()
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_REPLYTO)));
        
        Trace export = new Trace(uuid)
                .addBundle(new Account()
                        .setAccountType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_CATEGORY)))
                .addBundle(new DomainName()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DOMAIN)))
                .addBundle(new EmailMessage()
                        .setInReplyTo(inReplyToNode))
                .addBundle(new DigitalAccount()
                        .setDisplayName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME)))
                .addBundle(new AccountAuthentication()
                        .setPassword(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PASSWORD)))
                .addBundle(new PathRelation()
                        .setPath(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PATH)))
                .addBundle(new URL()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new DigitalAccount()
                        .setDisplayName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_NAME)));
        
        export.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));
        
        Trace applicationNode = new BlankTraceNode()
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        
        ApplicationAccount account = new ApplicationAccount()
                .setApplication(applicationNode);
        account.setId(getValueIfPresent(artifact, StandardAttributeTypes.TSK_USER_ID));
        account.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        export.addBundle(account);
        
        addToOutput(export, output);
        addToOutput(applicationNode, output);
        addToOutput(inReplyToNode, output);
    }
    
    private void assembleContact(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        EmailAddress homeAddress = new EmailAddress()
                .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_HOME));
        homeAddress.setTag("Home");
        
        EmailAddress workAddress = new EmailAddress()
                .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_OFFICE));
        workAddress.setTag("Work");
        
        PhoneAccount homePhone = new PhoneAccount()
                .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_HOME));
        homePhone.setTag("Home");
        
        PhoneAccount workPhone = new PhoneAccount()
                .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_OFFICE));
        workPhone.setTag("Work");
        
        PhoneAccount mobilePhone = new PhoneAccount()
                .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_MOBILE));
        mobilePhone.setTag("Mobile");
        
        Trace export = new Trace(uuid)
                .addBundle(new URL()
                        .setFullValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_URL)))
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL)))
                .addBundle(homeAddress)
                .addBundle(workAddress)
                .addBundle(new Contact()
                        .setContactName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME)))
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)))
                .addBundle(homePhone)
                .addBundle(workPhone)
                .addBundle(mobilePhone);
        addToOutput(export, output);
    }
    
    private void assembleMessage(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException, BlackboardJsonAttrUtil.InvalidJsonException {
        Trace applicationNode = new BlankTraceNode()
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MESSAGE_TYPE)));
        
        Trace senderNode = new BlankTraceNode()
                .addBundle(new EmailAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_EMAIL_FROM)));
        
        Trace fromNode = new BlankTraceNode()
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_FROM)));
        
        Trace toNode = new BlankTraceNode()
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_TO)));
        
        Trace export = new Trace(uuid)
                .addBundle(new Message()
                        .setMessageText(getValueIfPresent(artifact, StandardAttributeTypes.TSK_TEXT))
                        .setApplication(applicationNode)
                        .setSentTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME))
                        .setMessageType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DIRECTION))
                        .setId(getValueIfPresent(artifact, StandardAttributeTypes.TSK_THREAD_ID)))
                .addBundle(new EmailMessage()
                        .setSender(senderNode))
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)))
                .addBundle(new PhoneCall()
                        .setFrom(fromNode)
                        .setTo(toNode))
                .addBundle(new SMSMessage()
                        .setIsRead(getIntegerIfPresent(artifact, StandardAttributeTypes.TSK_READ_STATUS)));
        
        BlackboardAttribute attachments = artifact.getAttribute(StandardAttributeTypes.TSK_ATTACHMENTS);
        if (attachments != null) {
            MessageAttachments attachmentsContainer = BlackboardJsonAttrUtil.fromAttribute(attachments, MessageAttachments.class);
            List<MessageAttachments.Attachment> tskAttachments = new ArrayList<>();
            tskAttachments.addAll(attachmentsContainer.getUrlAttachments());
            tskAttachments.addAll(attachmentsContainer.getFileAttachments());
            
            tskAttachments.forEach((tskAttachment) -> {
                export.addBundle(new Attachment()
                        .setUrl(tskAttachment.getLocation())
                );
            });
        }
        
        addToOutput(export, output);
        addToOutput(applicationNode, output);
        addToOutput(senderNode, output);
        addToOutput(fromNode, output);
        addToOutput(toNode, output);
    }
    
    private void assembleMetadataExif(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Device()
                        .setManufacturer(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MAKE))
                        .setModel(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_MODEL)))
                .addBundle(new LatLongCoordinates()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)));
        
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_CREATED));
        addToOutput(export, output);
    }
    
    private void assembleCallog(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace fromNode = new BlankTraceNode()
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_FROM)));
        
        Trace toNode = new BlankTraceNode()
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER_TO)));
        
        Trace export = new Trace(uuid)
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)))
                .addBundle(new PhoneCall()
                        .setFrom(fromNode)
                        .setTo(toNode)
                        .setEndTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_END))
                        .setStartTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_START))
                        .setCallType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DIRECTION)))
                .addBundle(new Contact()
                        .setContactName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME)));
        
        addToOutput(export, output);
        addToOutput(toNode, output);
        addToOutput(fromNode, output);
    }
    
    private void assembleCalendarEntry(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid);
        
        CalendarEntry calendarEntry = new CalendarEntry()
                .setStartTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_START))
                .setEndTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME_END))
                .setEventType(getValueIfPresent(artifact, StandardAttributeTypes.TSK_CALENDAR_ENTRY_TYPE));
        
        calendarEntry.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DESCRIPTION));
        
        BlankLocationNode locationNode = new BlankLocationNode();
        locationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
        
        calendarEntry.setLocation(locationNode);
        export.addBundle(calendarEntry);
        
        addToOutput(export, output);
        addToOutput(locationNode, output);
    }
    
    private void assembleSpeedDialEntry(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new Contact()
                        .setContactName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME_PERSON)))
                .addBundle(new PhoneAccount()
                        .setPhoneNumber(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PHONE_NUMBER)));
        
        addToOutput(export, output);
    }
    
    private void assembleBluetoothPairing(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new MobileDevice()
                        .setBluetoothDeviceName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_DEVICE_NAME)))
                .addBundle(new MACAddress()
                        .setValue(getValueIfPresent(artifact, StandardAttributeTypes.TSK_MAC_ADDRESS)));
        
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        addToOutput(export, output);
    }
    
    private void assembleGpsBookmark(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new LatLongCoordinates()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)))
                .addBundle(new Application()
                        .setApplicationIdentifier(getValueIfPresent(artifact, StandardAttributeTypes.TSK_PROG_NAME)));
        
        SimpleAddress simpleAddress = new SimpleAddress();
        simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
        export.addBundle(simpleAddress);
        
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        export.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));
        addToOutput(export, output);
    }
    
    private void assembleGpsLastKnownLocation(String uuid, BlackboardArtifact artifact, List<JsonElement> output) throws TskCoreException {
        Trace export = new Trace(uuid)
                .addBundle(new LatLongCoordinates()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)));
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        
        BlankLocationNode locationNode = new BlankLocationNode();
        locationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));
        
        SimpleAddress simpleAddress = new SimpleAddress();
        simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
        export.addBundle(simpleAddress);
        
        addToOutput(export, output);
        addToOutput(locationNode, output);
        addToOutput(new BlankRelationshipNode()
                .setSource(locationNode.getId())
                .setTarget(export.getId()), output);
    }
    
    private void importGpsSearch(IdMapping mapping, Content content, UcoObject ucoObject) throws TskCoreException {
        if (!(ucoObject instanceof Trace)) {
            return Optional.empty();
        }
        
        Trace trace = (Trace) ucoObject;
        
        Optional<BlackboardAttribute> createdTime = getTimeStampAttr(TSK_DATETIME, CASE_UCO_SOURCE)
        Optional<LatLongCoordinates> Trace export = new Trace(uuid)
                .addBundle(new LatLongCoordinates()
                        .setAltitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_ALTITUDE))
                        .setLatitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LATITUDE))
                        .setLongitude(getDoubleIfPresent(artifact, StandardAttributeTypes.TSK_GEO_LONGITUDE)));
        export.setCreatedTime(getLongIfPresent(artifact, StandardAttributeTypes.TSK_DATETIME));
        
        BlankLocationNode locationNode = new BlankLocationNode();
        locationNode.setName(getValueIfPresent(artifact, StandardAttributeTypes.TSK_NAME));
        
        SimpleAddress simpleAddress = new SimpleAddress();
        simpleAddress.setDescription(getValueIfPresent(artifact, StandardAttributeTypes.TSK_LOCATION));
        export.addBundle(simpleAddress);
        
        addToOutput(export, output);
        addToOutput(locationNode, output);
        addToOutput(new BlankRelationshipNode()
                .setSource(locationNode.getId())
                .setTarget(export.getId()), output);
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
    
    private <T> Optional<T> getFirstPresent(Stream<Optional<T>> optionalStream) {
        return optionalStream
                .filter(Optional::isPresent)
                .map(Optional::get)
                .findFirst();
    }
    
    private <T> List<T> getFiltered(Optional<T>... items) {
        return Stream.of(items)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());
    }
    
    private <T extends UcoObject> List<T> getChildren(Trace parentTrace, Class<T> clazz) {
        return parentTrace.getHasPropertyBundle().stream()
                .filter((facet) -> clazz.isInstance(facet))
                .map((facet) -> (T) facet)
                .collect(Collectors.toList());
    }
    
    private <T extends UcoObject> Optional<T> getChild(Trace parentTrace, Class<T> clazz) {
        return parentTrace.getHasPropertyBundle().stream()
                .filter((facet) -> clazz.isInstance(facet))
                .map((facet) -> (T) facet)
                .findFirst();
    }
    
    private Optional<BlackboardAttribute> getTimeStampAttr(BlackboardAttribute.Type type, String value) {
        return getEpochTime(value)
                .flatMap((epochTime) -> getAttr(type, epochTime));
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
