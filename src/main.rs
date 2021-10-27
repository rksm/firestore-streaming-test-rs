use anyhow::Result;

use firestore_grpc::tonic::metadata::MetadataValue;
use firestore_grpc::tonic::transport::{Channel, ClientTlsConfig};
use firestore_grpc::tonic::{Request, Status};
use firestore_grpc::v1::firestore_client::FirestoreClient;
use firestore_grpc::v1::listen_request::TargetChange;
use firestore_grpc::v1::structured_query::CollectionSelector;
use firestore_grpc::v1::target::query_target::QueryType;
use firestore_grpc::v1::target::{DocumentsTarget, QueryTarget, TargetType};
use firestore_grpc::v1::{ListenRequest, StructuredQuery, Target};

use futures::{stream, StreamExt};
use std::{collections::HashMap, path::PathBuf};

mod auth;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let env_file = ".env";
    let _env_path = dotenv::from_filename(env_file).expect(".env");

    let cache_dir: PathBuf = "./data".into();
    std::fs::create_dir_all(&cache_dir)?;

    let acct = auth::FirebaseServiceAccount::from_default_env_var()?;
    let project_id = acct.project_id.clone();
    let scopes = [
        "https://www.googleapis.com/auth/firebase.database",
        "https://www.googleapis.com/auth/cloud-platform",
    ];
    let mut token = auth::GToken::new(acct, &scopes);
    let token = token.refresh_if_necessary().await?;

    streaming_test(project_id, token).await?;

    Ok(())
}

const URL: &str = "https://firestore.googleapis.com";
const DOMAIN: &str = "firestore.googleapis.com";

async fn streaming_test(project_id: String, token: String) -> Result<()> {
    let db = format!("projects/{}/databases/(default)", project_id);
    let parent = format!("projects/{}/databases/(default)/documents", project_id);
    let users_collection = format!(
        "projects/{}/databases/(default)/documents/users",
        project_id
    );

    let req = ListenRequest {
        database: db.clone(),
        labels: HashMap::new(),
        target_change: Some(TargetChange::AddTarget(Target {
            target_id: 0x52757374,
            once: false,
            target_type: Some(TargetType::Documents(DocumentsTarget {
                documents: vec![users_collection],
            })),
            resume_type: None,
        })),
    };

    // let req = ListenRequest {
    //     database: db.clone(),
    //     labels: HashMap::new(),
    //     target_change: Some(TargetChange::AddTarget(Target {
    //         // "Rust" in hex: https://github.com/googleapis/python-firestore/issues/51
    //         target_id: 0x52757374,
    //         once: false,
    //         target_type: Some(TargetType::Query(QueryTarget {
    //             parent,
    //             query_type: Some(QueryType::StructuredQuery(StructuredQuery {
    //                 select: None,
    //                 from: vec![CollectionSelector {
    //                     collection_id: users_collection,
    //                     all_descendants: true,
    //                 }],
    //                 r#where: None,
    //                 order_by: vec![],
    //                 start_at: None,
    //                 end_at: None,
    //                 offset: 0,
    //                 limit: Some(5),
    //             })),
    //         })),
    //         resume_type: None,
    //     })),
    // };

    let mut req = Request::new(stream::iter(vec![req]));
    let metadata = req.metadata_mut();
    metadata.insert(
        "google-cloud-resource-prefix",
        MetadataValue::from_str(&db).unwrap(),
    );
    let bearer_token = format!("Bearer {}", token);
    metadata.insert(
        "authorization",
        MetadataValue::from_str(&bearer_token).unwrap(),
    );

    println!("sending request");

    let endpoint = Channel::from_static(URL).tls_config(ClientTlsConfig::new().domain_name(DOMAIN));

    let bearer_token = format!("Bearer {}", token);
    let header_value = MetadataValue::from_str(&bearer_token)?;
    let db = format!("projects/{}/databases/(default)", project_id);
    let channel = endpoint.connect().await?;
    let mut service = FirestoreClient::with_interceptor(channel, move |mut req: Request<()>| {
        req.metadata_mut()
            .insert("authorization", header_value.clone());
        req.metadata_mut().insert(
            "google-cloud-resource-prefix",
            MetadataValue::from_str(&db).unwrap(),
        );

        Ok(req)
    });
    // get_client(&token, &project_id)

    let res = service.listen(req).await?;
    let mut res = res.into_inner();
    while let Some(msg) = res.next().await {
        println!("getting response");
        dbg!(msg);
    }

    println!("done");

    Ok(())
}
