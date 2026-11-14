# Known Exploited Vulnerabilities (KEV) Tracker
# ------------------------------------------------
# Interactive dashboard of CISA's Known Exploited Vulnerabilities catalog:
# vulnerabilities confirmed to be exploited in the wild, which organisations
# should patch first.
#
# Data: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
# On start-up the app tries to download the live CSV feed; if that fails it
# falls back to the snapshot bundled in data/.

suppressPackageStartupMessages({
  library(shiny)
  library(bslib)
  library(dplyr)
  library(tidyr)
  library(stringr)
  library(readr)
  library(plotly)
  library(DT)
})

# ---- Data -----------------------------------------------------------------
KEV_URL  <- "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv"
SNAPSHOT <- "data/known_exploited_vulnerabilities.csv"

load_kev <- function() {
  live <- tryCatch({
    tmp <- tempfile(fileext = ".csv")
    old <- options(timeout = 15); on.exit(options(old), add = TRUE)
    utils::download.file(KEV_URL, tmp, quiet = TRUE, mode = "wb")
    d <- read_csv(tmp, show_col_types = FALSE)
    stopifnot(all(c("cveID", "dateAdded", "dueDate") %in% names(d)), nrow(d) > 500)
    d
  }, error = function(e) NULL)
  if (!is.null(live)) return(list(data = live, source = "Live CISA feed"))
  list(data = read_csv(SNAPSHOT, show_col_types = FALSE), source = "Bundled snapshot")
}

loaded <- suppressWarnings(load_kev())
kev <- loaded$data |>
  mutate(
    dateAdded  = as.Date(dateAdded),
    dueDate    = as.Date(dueDate),
    cve_year   = as.integer(str_match(cveID, "CVE-(\\d{4})")[, 2]),
    year_added = as.integer(format(dateAdded, "%Y")),
    month      = as.Date(format(dateAdded, "%Y-%m-01")),
    age_years  = year_added - cve_year,
    window_days = as.integer(dueDate - dateAdded),
    ransomware = if_else(knownRansomwareCampaignUse == "Known", "Known", "Unknown"),
    cwes       = replace_na(cwes, "Not specified")
  )
DATA_AS_OF <- max(kev$dateAdded)
LAUNCH_MONTH <- min(kev$month)  # the catalog launched with a large initial batch

CWE_NAMES <- c(
  "CWE-20" = "Improper input validation", "CWE-78" = "OS command injection",
  "CWE-787" = "Out-of-bounds write", "CWE-416" = "Use after free",
  "CWE-119" = "Memory buffer bounds", "CWE-22" = "Path traversal",
  "CWE-94" = "Code injection", "CWE-502" = "Unsafe deserialization",
  "CWE-287" = "Improper authentication", "CWE-306" = "Missing auth for critical function",
  "CWE-843" = "Type confusion", "CWE-284" = "Improper access control",
  "CWE-122" = "Heap-based overflow", "CWE-77" = "Command injection",
  "CWE-79" = "Cross-site scripting", "CWE-89" = "SQL injection",
  "CWE-434" = "Unrestricted file upload", "CWE-918" = "Server-side request forgery",
  "CWE-125" = "Out-of-bounds read", "CWE-190" = "Integer overflow",
  "CWE-269" = "Improper privilege management", "CWE-862" = "Missing authorization",
  "CWE-863" = "Incorrect authorization", "CWE-200" = "Information exposure",
  "CWE-288" = "Auth bypass via alternate path", "CWE-352" = "Cross-site request forgery",
  "CWE-400" = "Uncontrolled resource consumption", "CWE-798" = "Hard-coded credentials",
  "CWE-476" = "NULL pointer dereference", "CWE-24" = "Path traversal (../)"
)
cwe_label <- function(id) ifelse(id %in% names(CWE_NAMES), paste0(id, " · ", CWE_NAMES[id]), id)

# ---- Design tokens (validated dark palette) -------------------------------
COL <- list(
  page = "#0f1520", card = "#161e2c", ink = "#f0efec", ink2 = "#c3c2b7",
  muted = "#8b93a1", grid = "#262f40",
  s1 = "#3987e5",  # series 1: blue  (Unknown ransomware use / single series)
  s2 = "#d95926"   # series 2: orange (Known ransomware use)
)
SEQ <- c("#1a2a44", "#184f95", "#256abf", "#3987e5", "#6da7ec", "#9ec5f4", "#cde2fb")

theme <- bs_theme(
  version = 5, bg = COL$page, fg = COL$ink, primary = COL$s1,
  secondary = COL$card, base_font = font_google("Inter", local = FALSE),
  code_font = font_google("JetBrains Mono", local = FALSE), "card-bg" = COL$card,
  "border-color" = COL$grid
)

style_plot <- function(p, ytitle = "", xtitle = "", legend = FALSE) {
  p |>
    layout(
      paper_bgcolor = "rgba(0,0,0,0)", plot_bgcolor = "rgba(0,0,0,0)",
      font = list(color = COL$ink2, family = "Inter, sans-serif", size = 12),
      xaxis = list(title = xtitle, gridcolor = COL$grid, zeroline = FALSE, linecolor = COL$grid),
      yaxis = list(title = ytitle, gridcolor = COL$grid, zeroline = FALSE),
      showlegend = legend,
      legend = list(orientation = "h", x = 0, y = 1.12, font = list(color = COL$ink2)),
      hoverlabel = list(bgcolor = COL$card, bordercolor = COL$grid, font = list(color = COL$ink)),
      margin = list(l = 10, r = 10, t = 30, b = 10), bargap = 0.15
    ) |>
    config(displayModeBar = FALSE)
}

empty_plot <- function() {
  plot_ly(x = numeric(0), y = numeric(0), type = "scatter", mode = "markers") |>
    layout(xaxis = list(visible = FALSE), yaxis = list(visible = FALSE),
           annotations = list(text = "No vulnerabilities match the filters", showarrow = FALSE,
                              font = list(color = COL$muted, size = 14))) |>
    style_plot()
}

# ---- UI -------------------------------------------------------------------
vendors <- kev |> count(vendorProject, sort = TRUE) |> pull(vendorProject)

sidebar_ui <- sidebar(
  width = 290, bg = COL$card,
  dateRangeInput("dates", "Date added to KEV", start = min(kev$dateAdded),
                 end = DATA_AS_OF, min = min(kev$dateAdded), max = DATA_AS_OF),
  selectizeInput("vendor", "Vendor", choices = vendors, multiple = TRUE,
                 options = list(placeholder = "All vendors")),
  radioButtons("ransom", "Known ransomware use",
               c("All" = "all", "Known only" = "Known", "Unknown only" = "Unknown")),
  textInput("search", "Search CVE, product or description", placeholder = "e.g. VPN, Exchange, CVE-2024"),
  hr(),
  div(class = "small", style = sprintf("color:%s", COL$ink2),
      strong("Data: "), loaded$source, br(),
      "Latest addition: ", format(DATA_AS_OF, "%d %b %Y"), br(),
      a("CISA KEV catalog", href = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        target = "_blank"))
)

overview_ui <- tagList(
  layout_columns(
    fill = FALSE, col_widths = c(3, 3, 3, 3),
    value_box("Exploited vulnerabilities", textOutput("vb_total"),
              theme = value_box_theme(bg = COL$card, fg = COL$ink)),
    value_box("Added in last 90 days", textOutput("vb_recent"),
              theme = value_box_theme(bg = COL$card, fg = COL$ink)),
    value_box("Linked to ransomware", textOutput("vb_ransom"),
              theme = value_box_theme(bg = COL$card, fg = COL$ink)),
    value_box("Vendors affected", textOutput("vb_vendors"),
              theme = value_box_theme(bg = COL$card, fg = COL$ink))
  ),
  card(
    full_screen = TRUE,
    card_header(
      class = "d-flex justify-content-between align-items-center",
      "New KEV entries per month, by known ransomware use",
      checkboxInput("hide_launch", "Hide launch batch (Nov 2021)", value = TRUE, width = "auto")
    ),
    plotlyOutput("monthly", height = "320px")
  ),
  layout_columns(
    col_widths = c(6, 6),
    card(full_screen = TRUE, card_header("Top 10 vendors"), plotlyOutput("vendors", height = "340px")),
    card(full_screen = TRUE, card_header("Top 10 weakness types (CWE)"), plotlyOutput("cwes", height = "340px"))
  )
)

insights_ui <- tagList(
  card(card_header("Key findings (calculated from the current filters)"), uiOutput("findings")),
  layout_columns(
    col_widths = c(6, 6),
    card(full_screen = TRUE,
         card_header("How old is a vulnerability when it's confirmed as exploited?"),
         plotlyOutput("age", height = "300px"),
         card_footer(class = "small text-secondary",
                     "Years between the CVE ID's year and the date CISA added it to KEV. ",
                     "Old, unpatched systems stay a target for a long time.")),
    card(full_screen = TRUE,
         card_header("Patch deadline given to U.S. federal agencies"),
         plotlyOutput("window", height = "300px"),
         card_footer(class = "small text-secondary",
                     "Days between dateAdded and dueDate. Most new entries get 21 days or less."))
  ),
  card(full_screen = TRUE,
       card_header("Top vendors by year added"),
       plotlyOutput("heatmap", height = "360px"))
)

explore_ui <- card(
  full_screen = TRUE, fill = FALSE, height = "auto",
  card_header(class = "d-flex justify-content-between align-items-center",
              "Catalog entries", downloadButton("download", "Download CSV", class = "btn-sm")),
  card_body(fillable = FALSE, DTOutput("table"))
)

about_ui <- card(
  card_body(
    class = "about",
    h4("About this dashboard"),
    p("CISA's Known Exploited Vulnerabilities (KEV) catalog lists vulnerabilities that ",
      strong("have been exploited in real attacks"), ". With tens of thousands of CVEs published every year, ",
      "KEV is one of the most practical signals for deciding what to patch first. U.S. federal agencies are ",
      "required to fix listed vulnerabilities by the due date, and many private organisations use it the same way."),
    h5("What this shows"),
    tags$ul(
      tags$li(strong("Overview:"), " how fast the catalog grows, which vendors and weakness types dominate, and how many entries are linked to ransomware."),
      tags$li(strong("Insights:"), " how old vulnerabilities are when they're confirmed as exploited, how long organisations get to patch, and how vendor exposure changes over time."),
      tags$li(strong("Explore:"), " a searchable table with links to the NVD entry for each CVE.")
    ),
    h5("Method notes"),
    tags$ul(
      tags$li("Age at listing = year added minus the year in the CVE ID. The CVE year is when the ID was reserved, which is usually close to disclosure."),
      tags$li("The catalog launched in November 2021 with a large initial batch, which is hidden by default in the monthly chart so it doesn't distort the scale."),
      tags$li("'Known' ransomware use means CISA has evidence of use in a ransomware campaign. 'Unknown' doesn't mean it's never been used."),
      tags$li("CWE counts include every CWE listed for each vulnerability, so one entry can count more than once.")
    ),
    h5("Built with"),
    p("R · Shiny · bslib · plotly · DT · dplyr. Part of my ",
      a("cybersecurity portfolio", href = "https://pulemolise.net/cybersecurity/kev-tracker/", target = "_blank"),
      ". Source code on ",
      a("GitHub", href = "https://github.com/pulemoliserr/kev-tracker-shiny", target = "_blank"), ".")
  )
)

ui <- page_navbar(
  title = tags$span(icon("shield-halved"), " KEV Tracker"),
  theme = theme, sidebar = sidebar_ui, fillable = FALSE,
  header = tags$head(tags$style(HTML(sprintf("
    .bslib-value-box .value-box-showcase .fa, .bslib-value-box .value-box-showcase svg{font-size:2rem!important;height:2rem!important;width:2rem!important;opacity:.85}
    .card-footer{color:%s!important}
    .bslib-value-box .value-box-title{color:%s;font-size:.85rem}
    .bslib-value-box .value-box-value{font-size:1.9rem;font-weight:600}
    .card-header{font-weight:600;color:%s;border-bottom:1px solid %s}
    .card-header .form-check{margin-bottom:0;font-weight:400;font-size:.85rem;color:%s}
    .card-header .shiny-input-container{margin-bottom:0}
    table.dataTable td{vertical-align:top;font-size:.85rem}
    table.dataTable td:nth-child(-n+3){white-space:nowrap}
    .about p, .about li{color:%s;max-width:75ch}
    a{color:%s}
  ", COL$ink2, COL$ink2, COL$ink, COL$grid, COL$ink2, COL$ink2, "#6da7ec")))),
  nav_panel("Overview", overview_ui),
  nav_panel("Insights", insights_ui),
  nav_panel("Explore", explore_ui),
  nav_panel("About", about_ui)
)

# ---- Server ---------------------------------------------------------------
server <- function(input, output, session) {

  filtered <- reactive({
    d <- kev |> filter(dateAdded >= input$dates[1], dateAdded <= input$dates[2])
    if (length(input$vendor)) d <- d |> filter(vendorProject %in% input$vendor)
    if (input$ransom != "all") d <- d |> filter(ransomware == input$ransom)
    q <- str_trim(input$search)
    if (nzchar(q)) {
      d <- d |> filter(if_any(c(cveID, vendorProject, product, vulnerabilityName, shortDescription),
                              ~ str_detect(.x, regex(q, ignore_case = TRUE, literal = TRUE))))
    }
    d
  })

  fmt <- function(x) format(x, big.mark = ",")

  output$vb_total   <- renderText(fmt(nrow(filtered())))
  output$vb_recent  <- renderText(fmt(sum(filtered()$dateAdded > DATA_AS_OF - 90)))
  output$vb_ransom  <- renderText({
    d <- filtered(); if (!nrow(d)) return("–")
    sprintf("%s (%.0f%%)", fmt(sum(d$ransomware == "Known")), 100 * mean(d$ransomware == "Known"))
  })
  output$vb_vendors <- renderText(fmt(n_distinct(filtered()$vendorProject)))

  output$monthly <- renderPlotly({
    d <- filtered()
    if (isTRUE(input$hide_launch)) d <- d |> filter(month != LAUNCH_MONTH)
    if (!nrow(d)) return(empty_plot())
    m <- d |> count(month, ransomware) |>
      complete(month = seq(min(month), max(month), by = "month"),
               ransomware = c("Unknown", "Known"), fill = list(n = 0)) |>
      mutate(ransomware = factor(ransomware, c("Unknown", "Known")))
    p <- plot_ly(m, x = ~month, y = ~n, color = ~ransomware, type = "bar",
            colors = c(Unknown = COL$s1, Known = COL$s2),
            marker = list(line = list(color = COL$card, width = 1)),
            hovertemplate = "%{x|%b %Y}<br>%{fullData.name} ransomware use: <b>%{y}</b><extra></extra>") |>
      layout(barmode = "stack") |>
      style_plot(ytitle = "Vulnerabilities added", xtitle = "", legend = TRUE) |>
      layout(legend = list(traceorder = "normal"))
    if (max(tapply(m$n, m$month, sum)) < 10) p <- p |> layout(yaxis = list(dtick = 1))
    p
  })

  hbar <- function(df, label, value, hover) {
    df <- df |> arrange(.data[[value]])
    plot_ly(df, y = factor(df[[label]], levels = df[[label]]), x = df[[value]], type = "bar",
            orientation = "h", marker = list(color = COL$s1, line = list(color = COL$card, width = 2)),
            text = df[[value]], textposition = "outside", textfont = list(color = COL$ink2),
            cliponaxis = FALSE, hovertemplate = hover) |>
      style_plot() |>
      layout(xaxis = list(showgrid = FALSE, showticklabels = FALSE),
             yaxis = list(gridcolor = "rgba(0,0,0,0)", ticksuffix = "  ",
                          range = c(nrow(df) - 10.5, nrow(df) - 0.5)))
  }

  output$vendors <- renderPlotly({
    d <- filtered(); if (!nrow(d)) return(empty_plot())
    top <- d |> count(vendorProject, name = "n", sort = TRUE) |> head(10)
    hbar(top, "vendorProject", "n", "%{y}: <b>%{x}</b> exploited vulnerabilities<extra></extra>")
  })

  output$cwes <- renderPlotly({
    d <- filtered(); if (!nrow(d)) return(empty_plot())
    top <- d |> separate_longer_delim(cwes, ", ") |> filter(cwes != "Not specified") |>
      count(cwes, name = "n", sort = TRUE) |> head(10) |> mutate(label = cwe_label(cwes))
    if (!nrow(top)) return(empty_plot())
    hbar(top, "label", "n", "%{y}<br><b>%{x}</b> vulnerabilities<extra></extra>")
  })

  output$age <- renderPlotly({
    d <- filtered(); if (!nrow(d)) return(empty_plot())
    brks <- c(-Inf, 0, 1, 2, 5, 10, Inf)
    labs <- c("Same year", "1 year", "2 years", "3–5 years", "6–10 years", "10+ years")
    a <- d |> mutate(b = cut(age_years, brks, labs)) |> count(b, .drop = FALSE) |>
      mutate(pct = 100 * n / sum(n))
    plot_ly(a, x = ~b, y = ~n, type = "bar",
            marker = list(color = COL$s1, line = list(color = COL$card, width = 2)),
            text = ~sprintf("%.0f%%", pct), textposition = "outside",
            textfont = list(color = COL$ink2), cliponaxis = FALSE,
            hovertemplate = "%{x}: <b>%{y}</b> vulnerabilities<extra></extra>") |>
      style_plot(ytitle = "Vulnerabilities", xtitle = "")
  })

  output$window <- renderPlotly({
    d <- filtered(); if (!nrow(d)) return(empty_plot())
    brks <- c(-Inf, 7, 14, 21, 60, Inf)
    labs <- c("≤ 7 days", "8–14 days", "15–21 days", "22–60 days", "> 60 days")
    w <- d |> mutate(b = cut(window_days, brks, labs)) |> count(b, .drop = FALSE) |>
      mutate(pct = 100 * n / sum(n))
    plot_ly(w, x = ~b, y = ~n, type = "bar",
            marker = list(color = COL$s1, line = list(color = COL$card, width = 2)),
            text = ~sprintf("%.0f%%", pct), textposition = "outside",
            textfont = list(color = COL$ink2), cliponaxis = FALSE,
            hovertemplate = "%{x}: <b>%{y}</b> vulnerabilities<extra></extra>") |>
      style_plot(ytitle = "Vulnerabilities", xtitle = "")
  })

  # per-cell labels: dark ink on light cells, light ink on dark cells
  cell_labels <- function(mat, rows) {
    hi <- max(mat)
    out <- list()
    for (i in seq_len(nrow(mat))) for (j in seq_len(ncol(mat))) {
      v <- mat[i, j]
      out[[length(out) + 1]] <- list(
        x = j - 1, y = i - 1, text = v, showarrow = FALSE,
        font = list(size = 11, color = if (hi > 0 && v / hi > 0.55) "#0f1520" else COL$ink))
    }
    out
  }

  output$heatmap <- renderPlotly({
    d <- filtered(); if (!nrow(d)) return(empty_plot())
    topv <- d |> count(vendorProject, sort = TRUE) |> head(10) |> pull(vendorProject)
    h <- d |> filter(vendorProject %in% topv) |> count(vendorProject, year_added) |>
      complete(vendorProject = topv, year_added = sort(unique(d$year_added)), fill = list(n = 0))
    z <- h |> pivot_wider(names_from = year_added, values_from = n) |>
      mutate(vendorProject = factor(vendorProject, rev(topv))) |> arrange(vendorProject)
    mat <- as.matrix(z[, -1])
    plot_ly(x = colnames(mat), y = as.character(z$vendorProject), z = mat, type = "heatmap",
            colorscale = lapply(seq_along(SEQ), function(i) list((i - 1) / (length(SEQ) - 1), SEQ[i])),
            xgap = 2, ygap = 2,
            colorbar = list(title = list(text = "Added", font = list(color = COL$ink2)),
                            tickfont = list(color = COL$ink2), outlinewidth = 0, thickness = 10),
            hovertemplate = "%{y} · %{x}: <b>%{z}</b> added<extra></extra>") |>
      style_plot() |>
      layout(xaxis = list(type = "category", gridcolor = "rgba(0,0,0,0)"),
             yaxis = list(gridcolor = "rgba(0,0,0,0)", ticksuffix = "  "),
             annotations = cell_labels(mat, as.character(z$vendorProject)))
  })

  output$findings <- renderUI({
    d <- filtered()
    if (nrow(d) < 5) return(p(class = "text-secondary", "Not enough data for the current filters."))
    pct <- function(x) sprintf("%.0f%%", 100 * mean(x))
    top_v <- d |> count(vendorProject, sort = TRUE) |> slice(1)
    top_p <- d |> count(vendorProject, product, sort = TRUE) |> slice(1)
    top_c <- d |> separate_longer_delim(cwes, ", ") |> filter(cwes != "Not specified") |>
      count(cwes, sort = TRUE) |> slice(1)
    old <- sum(d$age_years > 5)
    std <- as.integer(names(sort(table(d$window_days), decreasing = TRUE))[1])
    tags$ul(
      tags$li(strong(top_v$vendorProject), sprintf(" accounts for %s of entries (%s); its most-listed product is %s (%s).",
              pct(d$vendorProject == top_v$vendorProject), fmt(top_v$n), top_p$product, fmt(top_p$n))),
      tags$li(strong(pct(d$age_years <= 0)), " were confirmed as exploited in the same year their CVE was assigned, so attackers move quickly once a flaw is known."),
      tags$li(strong(fmt(old)), sprintf(" vulnerabilities (%s) were more than 5 years old when they were added. Legacy and unpatched systems remain a target.", pct(d$age_years > 5))),
      if (nrow(top_c)) tags$li("The most common weakness is ", strong(cwe_label(top_c$cwes)),
                               sprintf(" (%s entries). Many of the top CWEs are memory-safety and injection flaws.", fmt(top_c$n))),
      tags$li(strong(pct(d$ransomware == "Known")), " are known to have been used in ransomware campaigns."),
      tags$li("The most common patch deadline is ", strong(paste(std, "days")), " after a vulnerability is added.")
    )
  })

  table_data <- reactive({
    filtered() |>
      arrange(desc(dateAdded)) |>
      transmute(
        CVE = sprintf('<a href="https://nvd.nist.gov/vuln/detail/%s" target="_blank">%s</a>', cveID, cveID),
        Added = dateAdded, Due = dueDate, Vendor = vendorProject, Product = product,
        Ransomware = ransomware, CWE = cwes,
        Description = shortDescription
      )
  })

  output$table <- renderDT({
    datatable(
      table_data(), escape = FALSE, rownames = FALSE, filter = "none", class = "compact",
      options = list(pageLength = 15, scrollX = TRUE, dom = "tip",
                     columnDefs = list(list(width = "420px", targets = 7)))
    ) |>
      formatStyle(names(table_data()), color = COL$ink2, backgroundColor = COL$card)
  })

  output$download <- downloadHandler(
    filename = function() paste0("kev_filtered_", Sys.Date(), ".csv"),
    content = function(file) write_csv(filtered() |> select(-month), file)
  )
}

shinyApp(ui, server)
