//! The Programs page's models (package UI-MODEL-A): the list rules ([`rules`], `ProgramRules.cs`), the
//! entries with their patches and details ([`entries`], `Inventory.cs`/`ProgramEntries.cs`), the
//! expected-leftovers shapes ([`forecast`], `Forecast.cs`), one list row ([`row`], `ProgramRow.cs`) and
//! the page itself ([`page::ProgramsModel`], the logic of `ProgramsView.xaml.cs`).

pub mod date;
pub mod entries;
pub mod forecast;
pub mod page;
pub mod row;
pub mod rules;
pub mod strings;

pub use date::{CivilDate, Clock, LocalOffset};
pub use entries::{ProgramEntry, ProgramIcon};
pub use forecast::{ForecastLine, ForecastLineKind, ForecastVerdict, LeftoverForecast};
pub use page::{
    BrokerUsers, EngineState, Filter, Filters, PageLayout, ProgramCommand, ProgramsModel,
    ProgramsPageView, ProgramsRequest, SortKey,
};
pub use row::ProgramRow;
pub use rules::{ListColumns, ProgramTab};

#[cfg(test)]
mod tests;
