// Copyright © 2016, Canal TP and/or its affiliates. All rights reserved.
//
// This file is part of Navitia,
//     the software to build cool stuff with public transport.
//
// Hope you'll enjoy and contribute to this project,
//     powered by Canal TP (www.canaltp.fr).
// Help us simplify mobility and open public transport:
//     a non ending quest to the responsive locomotion way of traveling!
//
// LICENCE: This program is free software; you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public
// License as published by the Free Software Foundation, either
// version 3 of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see
// <http://www.gnu.org/licenses/>.
//
// Stay tuned using
// twitter @navitia
// IRC #navitia on freenode
// https://groups.google.com/d/forum/navitia
// www.navitia.io
use super::query;
use hyper::mime::Mime;
use iron::status::Status as IronStatus;
use iron::typemap::Key;
use mimir::rubber::Rubber;
use model;
use model::v1::*;
use params::{
    coord_param, dataset_param, get_param_array, paginate_param, shape_param, timeout_param,
    types_param,
};
use prometheus;
use prometheus::Encoder;
use rustless;
use rustless::server::header;
use rustless::{Api, Nesting};
use serde;
use serde_json;
use std::time;
use valico::json_dsl;

use cosmogony::ZoneType;
use mimir;
use navitia_model::objects::Coord;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

const DEFAULT_LIMIT: u64 = 10u64;
const DEFAULT_OFFSET: u64 = 0u64;

struct Timer;
impl Key for Timer {
    type Value = prometheus::HistogramTimer;
}

lazy_static! {
    static ref HTTP_COUNTER: prometheus::CounterVec = register_counter_vec!(
        "bragi_http_requests_total",
        "Total number of HTTP requests made.",
        &["handler", "method", "status"]
    ).unwrap();
    static ref HTTP_REQ_HISTOGRAM: prometheus::HistogramVec = register_histogram_vec!(
        "bragi_http_request_duration_seconds",
        "The HTTP request latencies in seconds.",
        &["handler", "method"],
        prometheus::exponential_buckets(0.001, 1.5, 25).unwrap()
    ).unwrap();
}

/// get the timeout from the query 'timeout' parameter
/// if the param is not there, use the default value
fn parse_timeout(
    params: &rustless::json::JsonValue,
    default_timeout: Option<time::Duration>,
) -> Option<time::Duration> {
    params
        .find("timeout")
        .and_then(|v| v.as_u64())
        .map(time::Duration::from_millis)
        .or(default_timeout)
}

fn add_distance(autocomp_resp: &mut model::Autocomplete, origin_coord: &Coord) {
    for feature in &mut autocomp_resp.features {
        if let ::geojson::Value::Point(p) = &feature.geometry.value {
            if let [mut lon, mut lat] = p.as_slice() {
                let feature_coord = Coord { lon, lat };
                feature.distance = Some(feature_coord.distance_to(&origin_coord) as u32);
            }
        }
    }
}

fn remove_duplicates(response: &mut model::v1::AutocompleteResponse) {
    if let model::v1::AutocompleteResponse::Autocomplete(resp) = response {
        let old_features = resp.features.clone();
        let mut new_features: Vec<(usize, model::Feature)> = Vec::new();

        let mut features_map: BTreeMap<_, _> = old_features
            .into_iter()
            .enumerate()
            .map(|(i, f)| (make_key(&f), (i, f)))
            .collect();
        let mut postcode_map: HashMap<(&Option<String>, &Option<String>), Option<String>> =
            HashMap::new();

        for ((name, label, code, admin), (ref i, ref mut f)) in features_map.iter_mut() {
            if postcode_map.contains_key(&(name, label)) {
                let temp_code = postcode_map.get(&(name, label)).unwrap().clone();
                if code == &temp_code {
                    f.properties.geocoding.label = Some(format!(
                        "{} {}",
                        label.clone().unwrap(),
                        admin.clone().unwrap()
                    ));
                } else {
                    f.properties.geocoding.label = Some(format!(
                        "{} {}",
                        label.clone().unwrap(),
                        code.clone().unwrap()
                    ));
                }
            }
            postcode_map.insert((name, label), f.properties.geocoding.postcode.clone());
            new_features.push((*i, f.clone()));
        }
        new_features.sort_by_key(|(i, _f)| i.clone());
        resp.features = new_features
            .iter()
            .map(|(_k, f)| f.clone())
            .collect::<Vec<_>>();
    }

    fn smallest_admin(admins: &Vec<Arc<mimir::Admin>>) -> Option<String> {
        let mut zones: Vec<Option<ZoneType>> = Vec::new();

        zones.extend(admins.iter().map(|a| a.clone().zone_type));
        zones.sort();

        if !zones.is_empty() {
            match zones[0] {
                Some(ZoneType::Suburb) => Some("Suburb".to_string()),
                Some(ZoneType::CityDistrict) => Some("CityDistrict".to_string()),
                Some(ZoneType::City) => Some("City".to_string()),
                Some(ZoneType::StateDistrict) => Some("StateDistrict".to_string()),
                Some(ZoneType::State) => Some("State".to_string()),
                Some(ZoneType::CountryRegion) => Some("CountryRegion".to_string()),
                Some(ZoneType::Country) => Some("Country".to_string()),
                Some(ZoneType::NonAdministrative) => Some("NonAdministrative".to_string()),
                _ => None,
            }
        } else {
            None
        }
    }

    fn make_key(
        f: &model::Feature,
    ) -> (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        (
            f.properties.geocoding.name.clone(),
            f.properties.geocoding.label.clone(),
            f.properties.geocoding.postcode.clone(),
            smallest_admin(&f.properties.geocoding.administrative_regions),
        )
    }
}

fn render<T>(
    mut client: rustless::Client,
    obj: T,
) -> Result<rustless::Client, rustless::ErrorResponse>
where
    T: serde::Serialize + model::v1::HasStatus,
{
    client.set_json_content_type();
    client.set_header(header::AccessControlAllowOrigin::Any);
    client.set_status(obj.status());
    client.text(serde_json::to_string(&obj).unwrap())
}

pub struct ApiEndPoint {
    pub es_cnx_string: String,
    pub default_es_timeout: Option<time::Duration>,
}

impl ApiEndPoint {
    pub fn root(&self) -> rustless::Api {
        Api::build(|api| {
            api.get("", |endpoint| {
                endpoint.handle(|client, _params| {
                    let desc = EndPoint {
                        description: "autocomplete service".to_string(),
                    };
                    render(client, desc)
                })
            });

            api.error_formatter(|error, _media| {
                let err = if error.is::<rustless::errors::Validation>() {
                    let val_err = error.downcast::<rustless::errors::Validation>().unwrap();
                    // TODO better message, we shouldn't use {:?} but access the `path`
                    // and `detail` of all errrors in val_err.reason
                    CustomError {
                        short: "validation error".to_string(),
                        long: format!("invalid arguments {:?}", val_err.reason),
                        status: IronStatus::BadRequest,
                    }
                } else {
                    CustomError {
                        short: "bad_request".to_string(),
                        long: format!("bad request, error: {}", error),
                        status: IronStatus::BadRequest,
                    }
                };
                let mut resp = rustless::Response::from(
                    err.status,
                    Box::new(serde_json::to_string(&err).unwrap()),
                );
                resp.set_json_content_type();
                Some(resp)
            });

            api.before(|client, _params| {
                let method = client.endpoint.method.to_string();

                HTTP_REQ_HISTOGRAM
                    .get_metric_with(&labels!{
                        "handler" => client.endpoint.path.path.as_str(),
                        "method" => method.as_str(),
                    }).map(|timer| {
                        client.ext.insert::<Timer>(timer.start_timer());
                    }).unwrap_or_else(|err| {
                        error!("impossible to get HTTP_REQ_HISTOGRAM metrics";
                               "err" => err.to_string());
                    });
                Ok(())
            });

            api.after(|client, _params| {
                let method = client.endpoint.method.to_string();
                let code = client.status().to_string();

                HTTP_COUNTER
                    .get_metric_with(&labels!{
                        "handler" => client.endpoint.path.path.as_str(),
                        "method" => method.as_str(),
                        "status" => code.as_str(),
                    }).map(|counter| counter.inc())
                    .unwrap_or_else(|err| {
                        error!("impossible to get HTTP_COUNTER metrics"; "err" => err.to_string());
                    });
                client
                    .ext
                    .remove::<Timer>()
                    .map(|timer| timer.observe_duration())
                    .unwrap_or_else(|| error!("impossible to get timers from typemap"));
                Ok(())
            });
            api.mount(self.v1());
        })
    }

    fn v1(&self) -> rustless::Api {
        Api::build(|api| {
            api.mount(self.status());
            api.mount(self.autocomplete());
            api.mount(self.features());
            api.mount(self.reverse());
            api.mount(self.metrics());
        })
    }

    fn status(&self) -> rustless::Api {
        Api::build(|api| {
            api.get("status", |endpoint| {
                let cnx = self.es_cnx_string.clone();
                endpoint.handle(move |client, _params| {
                    let status = Status {
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        es: cnx.to_string(),
                        status: "good".to_string(),
                    };
                    render(client, status)
                })
            });
        })
    }

    fn metrics(&self) -> rustless::Api {
        Api::build(|api| {
            api.get("metrics", |endpoint| {
                endpoint.handle(move |mut client, _params| {
                    let encoder = prometheus::TextEncoder::new();
                    let metric_familys = prometheus::gather();
                    let mut buffer = vec![];
                    encoder.encode(&metric_familys, &mut buffer).unwrap();
                    client.set_content_type(encoder.format_type().parse::<Mime>().unwrap());
                    client.text(String::from_utf8(buffer).unwrap())
                })
            });
        })
    }

    fn reverse(&self) -> rustless::Api {
        Api::build(|api| {
            api.get("reverse", |endpoint| {
                endpoint.params(|params| {
                    coord_param(params, false);
                    timeout_param(params);
                });
                let cnx = self.es_cnx_string.clone();
                let default_timeout = self.default_es_timeout.clone();
                endpoint.handle(move |client, params| {
                    let coord = ::mimir::Coord::new(
                        params.find("lon").and_then(|p| p.as_f64()).unwrap(),
                        params.find("lat").and_then(|p| p.as_f64()).unwrap(),
                    );
                    let mut rubber = Rubber::new(&cnx);
                    let timeout = parse_timeout(params, default_timeout);
                    rubber.set_read_timeout(timeout);
                    rubber.set_write_timeout(timeout);
                    let model_autocomplete =
                        rubber.get_address(&coord).map_err(model::BragiError::from);

                    let response = model::v1::AutocompleteResponse::from(model_autocomplete);
                    render(client, response)
                })
            });
        })
    }

    fn features(&self) -> rustless::Api {
        Api::build(|api| {
            api.get("features/:id", |endpoint| {
                endpoint.params(|params| {
                    params.opt_typed("id", json_dsl::string());
                    dataset_param(params);
                    timeout_param(params);
                });

                let cnx = self.es_cnx_string.clone();
                let default_timeout = self.default_es_timeout.clone();
                endpoint.handle(move |client, params| {
                    let id = params.find("id").unwrap().as_str().unwrap();
                    let pt_datasets = get_param_array(params, "pt_dataset");
                    let all_data = params
                        .find("_all_data")
                        .map_or(false, |val| val.as_bool().unwrap());
                    let timeout = parse_timeout(params, default_timeout);
                    let features = query::features(&pt_datasets, all_data, &cnx, &id, timeout);
                    let response = model::v1::AutocompleteResponse::from(features);
                    render(client, response)
                })
            });
        })
    }

    fn autocomplete(&self) -> rustless::Api {
        Api::build(|api| {
            api.post("autocomplete", |endpoint| {
                endpoint.params(|params| {
                    params.opt_typed("q", json_dsl::string());
                    dataset_param(params);
                    paginate_param(params);
                    shape_param(params);
                    types_param(params);
                    timeout_param(params);
                });

                let cnx = self.es_cnx_string.clone();
                let default_timeout = self.default_es_timeout.clone();
                endpoint.handle(move |client, params| {
                    let q = params
                        .find("q")
                        .and_then(|val| val.as_str())
                        .unwrap_or("")
                        .to_string();
                    let pt_datasets = get_param_array(params, "pt_dataset");
                    let all_data = params
                        .find("_all_data")
                        .map_or(false, |val| val.as_bool().unwrap());
                    let offset = params
                        .find("offset")
                        .and_then(|val| val.as_u64())
                        .unwrap_or(DEFAULT_OFFSET);
                    let limit = params
                        .find("limit")
                        .and_then(|val| val.as_u64())
                        .unwrap_or(DEFAULT_LIMIT);
                    let geometry = params.find_path(&["shape", "geometry"]).unwrap();
                    let coordinates = geometry
                        .find_path(&["coordinates"])
                        .unwrap()
                        .as_array()
                        .unwrap();
                    let mut shape = Vec::new();
                    for ar in coordinates[0].as_array().unwrap() {
                        // (Lat, Lon)
                        shape.push((
                            ar.as_array().unwrap()[1].as_f64().unwrap(),
                            ar.as_array().unwrap()[0].as_f64().unwrap(),
                        ));
                    }
                    let types = get_param_array(params, "type");
                    let timeout = parse_timeout(params, default_timeout);
                    let model_autocomplete = query::autocomplete(
                        &q,
                        &pt_datasets,
                        all_data,
                        offset,
                        limit,
                        None,
                        &cnx,
                        Some(shape),
                        &types,
                        timeout,
                    );
                    let mut response = model::v1::AutocompleteResponse::from(model_autocomplete);

                    remove_duplicates(&mut response);

                    render(client, response)
                })
            });
            api.get("autocomplete", |endpoint| {
                endpoint.params(|params| {
                    params.opt_typed("q", json_dsl::string());
                    dataset_param(params);
                    paginate_param(params);
                    coord_param(params, true);
                    types_param(params);
                    timeout_param(params);
                });
                let cnx = self.es_cnx_string.clone();
                let default_timeout = self.default_es_timeout.clone();
                endpoint.handle(move |client, params| {
                    let q = params
                        .find("q")
                        .and_then(|val| val.as_str())
                        .unwrap_or("")
                        .to_string();
                    let pt_datasets = get_param_array(params, "pt_dataset");
                    let all_data = params
                        .find("_all_data")
                        .map_or(false, |val| val.as_bool().unwrap());
                    let offset = params
                        .find("offset")
                        .and_then(|val| val.as_u64())
                        .unwrap_or(DEFAULT_OFFSET);
                    let limit = params
                        .find("limit")
                        .and_then(|val| val.as_u64())
                        .unwrap_or(DEFAULT_LIMIT);
                    let lon = params.find("lon").and_then(|p| p.as_f64());
                    let lat = params.find("lat").and_then(|p| p.as_f64());
                    // we have already checked that if there is a lon, lat
                    // is not None so we can unwrap
                    let coord = lon.and_then(|lon| {
                        Some(Coord {
                            lon: lon,
                            lat: lat.unwrap(),
                        })
                    });

                    let types = get_param_array(params, "type");
                    let timeout = parse_timeout(params, default_timeout);
                    let model_autocomplete = query::autocomplete(
                        &q,
                        &pt_datasets,
                        all_data,
                        offset,
                        limit,
                        coord,
                        &cnx,
                        None,
                        &types,
                        timeout,
                    );

                    let mut response = model::v1::AutocompleteResponse::from(model_autocomplete);

                    // Optional : add distance for each feature (in meters)
                    use model::v1::AutocompleteResponse::Autocomplete;
                    if let (Some(coord), Autocomplete(autocomplete_resp)) = (&coord, &mut response)
                    {
                        add_distance(autocomplete_resp, coord);
                    }

                    remove_duplicates(&mut response);

                    render(client, response)
                })
            });
        })
    }
}

#[allow(dead_code)]
fn get_feature(
    nme: Option<String>,
    lbl: Option<String>,
    cde: Option<String>,
    adm_name: String,
    zt_adm: Option<ZoneType>,
) -> model::Feature {
    use geojson::{Geometry, Value};
    model::Feature {
        feature_type: "Feature_type".to_string(),
        geometry: Geometry::new(Value::Point(vec![-120.66029, 35.2812])),
        properties: model::Properties {
            geocoding: model::GeocodingResponse {
                name: nme,
                label: lbl,
                postcode: cde,
                administrative_regions: vec![Arc::new(mimir::Admin {
                    id: "".to_string(),
                    insee: "".to_string(),
                    level: 8,
                    label: "".to_string(),
                    name: adm_name,
                    zip_codes: vec![],
                    weight: 0.0,
                    coord: mimir::Coord::new(50.0, 50.0),
                    boundary: None,
                    bbox: None,
                    zone_type: zt_adm,
                    parent_id: None,
                    codes: vec![mimir::Code {
                        name: "".to_string(),
                        value: "".to_string(),
                    }],
                })],
                id: "".to_string(),
                place_type: "".to_string(),
                housenumber: None,
                street: None,
                city: None,
                citycode: None,
                level: None,
                poi_types: vec![],
                properties: vec![],
                address: None,
                commercial_modes: vec![],
                comments: vec![],
                physical_modes: vec![],
                timezone: None,
                codes: vec![],
                feed_publishers: vec![],
                bbox: None,
            },
        },
        distance: None,
    }
}

#[allow(dead_code)]
fn get_features() -> Vec<model::Feature> {
    let mut features: Vec<model::Feature> = Vec::new();
    features.push(get_feature(
        Some("2 Rue du Doublon".to_string()),
        Some("2 Rue du Doublon (Paris)".to_string()),
        Some("75012".to_string()),
        "".to_string(),
        Some(ZoneType::City),
    ));

    // Same feature as above: it's a duplicate that we want to remove
    features.push(get_feature(
        Some("2 Rue du Doublon".to_string()),
        Some("2 Rue du Doublon (Paris)".to_string()),
        Some("75012".to_string()),
        "".to_string(),
        Some(ZoneType::City),
    ));

    // Same feature as above but with a different postcode: so we keep it
    features.push(get_feature(
        Some("2 Rue du Doublon".to_string()),
        Some("2 Rue du Doublon (Paris)".to_string()),
        Some("75002".to_string()),
        "".to_string(),
        Some(ZoneType::City),
    ));

    // Same feature as above with the same postcode but with a smallest admin, so we keep it
    features.push(get_feature(
        Some("2 Rue du Doublon".to_string()),
        Some("2 Rue du Doublon (Paris)".to_string()),
        Some("75002".to_string()),
        "".to_string(),
        Some(ZoneType::Suburb),
    ));
    features
}

#[allow(dead_code)]
fn get_fake_response() -> model::v1::AutocompleteResponse {
    let autocomplete = model::Autocomplete {
        format_type: "FeatureCollection".to_string(),
        geocoding: model::Geocoding::new("0.1.0".to_string(), Some("".to_string())),
        features: get_features(),
    };
    model::v1::AutocompleteResponse::Autocomplete(autocomplete)
}

#[test]
fn test_remove_duplicates() {
    // First we create a bragi response with 3 features inside
    let mut responses = get_fake_response();

    // We check that "responses" contains 4 features at the begining
    if let model::v1::AutocompleteResponse::Autocomplete(ref resp) = responses {
        assert_eq!(resp.features.len(), 4);
    }

    // We remove the duplicate features from the response
    remove_duplicates(&mut responses);

    // We check that only two features remain
    if let model::v1::AutocompleteResponse::Autocomplete(resp) = responses {
        assert_eq!(resp.features.len(), 3);
    }
}
