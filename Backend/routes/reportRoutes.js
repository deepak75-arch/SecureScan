
import express from "express";
import PDFDocument from "pdfkit";
import requireScanAccess from "../middleware/requireScanAccess.js";


const router = express.Router();


const COLORS = {
  navy: "#14243A",
  blue: "#2563EB",
  background: "#F4F7FB",
  text: "#263445",
  muted: "#718096",
  border: "#E2E8F0",
  white: "#FFFFFF",
  green: "#15803D",
  red: "#DC2626",
  orange: "#EA580C",
  yellow: "#CA8A04",
  gray: "#64748B",
};

const PAGE = {
  left: 42,
  right: 42,
  top: 42,
  bottom: 58,
};

router.get(
  "/:scanId/pdf",
  requireScanAccess,
  async (req, res, next) => {
    try {
      const scan = req.scan;

      if (scan.status !== "completed") {
        return res.status(409).json({
          success: false,
          message: "Report is available only after scan completion.",
          currentStatus: scan.status,
        });
      }

    const findings = Array.isArray(scan.findings)
      ? scan.findings
      : [];

    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    findings.forEach((finding) => {
      const severity = String(
        finding.severity || "info"
      ).toLowerCase();

      if (Object.hasOwn(counts, severity)) {
        counts[severity]++;
      } else {
        counts.info++;
      }
    });

    const projectName = String(
      scan.projectName || "Untitled Project"
    )
      .replace(/[^\w -]/g, "")
      .slice(0, 55);

    const safeScanId = String(
      scan.scanId || req.params.scanId
    ).replace(/[^a-zA-Z0-9-]/g, "");

    const filename =
      `SecureScan_${projectName.replace(/\s+/g, "_")}_${safeScanId}.pdf`;

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename}"`
    );
    res.setHeader("Cache-Control", "no-store");

    const doc = new PDFDocument({
      size: "A4",
      margins: {
        top: PAGE.top,
        bottom: PAGE.bottom,
        left: PAGE.left,
        right: PAGE.right,
      },
      bufferPages: true,
      info: {
        Title: `Security Assessment - ${projectName}`,
        Author: "Secure Scan",
        Subject: "Automated Security Assessment Report",
      },
    });

    doc.on("error", (error) => {
      console.error("PDF generation error:", error);

      if (!res.headersSent) {
        res.status(500).end();
      } else {
        res.destroy(error);
      }
    });

    doc.pipe(res);

    const pageWidth = doc.page.width;
    const pageHeight = doc.page.height;

    const contentWidth =
      pageWidth - PAGE.left - PAGE.right;

    const contentBottom = pageHeight - 68;

    let y = 135;

    // ------------------------------------
    // TEXT HELPER
    // ------------------------------------

    function drawText(value, x, top, options = {}) {
      const {
        bold = false,
        size = 9,
        color = COLORS.text,
        ...pdfOptions
      } = options;

      doc
        .font(bold ? "Helvetica-Bold" : "Helvetica")
        .fontSize(size)
        .fillColor(color)
        .text(String(value ?? "N/A"), x, top, {
          lineGap: 2,
          ...pdfOptions,
        });
    }

    // ------------------------------------
    // SECTION TITLE
    // ------------------------------------

    function sectionTitle(title, top) {
      drawText(title.toUpperCase(), PAGE.left, top, {
        bold: true,
        size: 9,
        color: COLORS.blue,
        characterSpacing: 0.8,
      });

      return top + 22;
    }

    // ------------------------------------
    // PAGE MANAGEMENT
    // ------------------------------------

    function addContentPage() {
      doc.addPage();
      y = PAGE.top;
    }

    function ensureSpace(requiredHeight) {
      if (y + requiredHeight > contentBottom) {
        addContentPage();
      }
    }

    // ------------------------------------
    // HEADER
    // ------------------------------------

    function drawHeader() {
      doc
        .rect(0, 0, pageWidth, 112)
        .fill(COLORS.navy);

      drawText("SECURE SCAN", PAGE.left, 32, {
        bold: true,
        size: 24,
        color: COLORS.white,
      });

      drawText(
        "APPLICATION SECURITY ASSESSMENT",
        PAGE.left,
        65,
        {
          size: 9,
          color: "#CBD5E1",
          characterSpacing: 1.1,
        }
      );

      doc
        .roundedRect(
          pageWidth - 145,
          35,
          103,
          27,
          7
        )
        .fill("#1E3A5F");

      drawText(
        "COMPLETED",
        pageWidth - 145,
        44,
        {
          bold: true,
          size: 8,
          color: "#86EFAC",
          width: 103,
          align: "center",
        }
      );
    }

    // ------------------------------------
    // PROJECT OVERVIEW
    // ------------------------------------

    function drawProjectOverview() {
      y = sectionTitle("01 Project overview", y);

      const cardY = y;
      const cardHeight = 112;

      doc
        .roundedRect(
          PAGE.left,
          cardY,
          contentWidth,
          cardHeight,
          9
        )
        .fill(COLORS.background);

      const columnGap = 24;

      const columnWidth =
        (contentWidth - columnGap) / 2;

      const leftX = PAGE.left + 16;

      const rightX =
        leftX + columnWidth + columnGap;

      function detail(label, value, x, rowY, colWidth) {
        drawText(label.toUpperCase(), x, rowY, {
          bold: true,
          size: 7,
          color: COLORS.muted,
        });

        drawText(value || "N/A", x, rowY + 12, {
          size: 9,
          color: COLORS.text,
          width: colWidth,
        });
      }

      detail(
        "Project name",
        projectName,
        leftX,
        cardY + 15,
        columnWidth
      );

      detail(
        "Scan ID",
        scan.scanId,
        rightX,
        cardY + 15,
        columnWidth
      );

      detail(
        "Files scanned",
        scan.totalFiles ?? 0,
        leftX,
        cardY + 55,
        columnWidth
      );

      detail(
        "Completed on",
        scan.completedAt
          ? new Date(scan.completedAt).toLocaleString("en-IN")
          : "N/A",
        rightX,
        cardY + 55,
        columnWidth
      );

      y = cardY + cardHeight + 24;
    }

    // ------------------------------------
    // SECURITY SUMMARY
    // ------------------------------------

    function drawSecuritySummary() {
      y = sectionTitle("02 Security summary", y);

      const summaryY = y;
      const summaryHeight = 76;
      const summaryGap = 8;

      const summaryWidth =
        (contentWidth - summaryGap * 4) / 5;

      const summaryItems = [
        {
          label: "CRITICAL",
          value: counts.critical,
          color: COLORS.red,
        },
        {
          label: "HIGH",
          value: counts.high,
          color: COLORS.orange,
        },
        {
          label: "MEDIUM",
          value: counts.medium,
          color: COLORS.yellow,
        },
        {
          label: "LOW",
          value: counts.low,
          color: COLORS.blue,
        },
        {
          label: "INFO",
          value: counts.info,
          color: COLORS.gray,
        },
      ];

      summaryItems.forEach((item, index) => {
        const x =
          PAGE.left + index * (summaryWidth + summaryGap);

        doc
          .roundedRect(
            x,
            summaryY,
            summaryWidth,
            summaryHeight,
            7
          )
          .fill(COLORS.background);

        doc
          .roundedRect(x, summaryY, summaryWidth, 4, 2)
          .fill(item.color);

        drawText(item.value, x, summaryY + 17, {
          bold: true,
          size: 22,
          color: item.color,
          width: summaryWidth,
          align: "center",
        });

        drawText(item.label, x, summaryY + 51, {
          bold: true,
          size: 7,
          color: COLORS.muted,
          width: summaryWidth,
          align: "center",
        });
      });

      y = summaryY + summaryHeight + 16;

      doc
        .roundedRect(
          PAGE.left,
          y,
          contentWidth,
          35,
          7
        )
        .fill("#EFF6FF");

      drawText(
        "TOTAL SECURITY FINDINGS",
        PAGE.left + 13,
        y + 12,
        {
          bold: true,
          size: 8,
          color: COLORS.navy,
        }
      );

      drawText(
        findings.length,
        PAGE.left + contentWidth - 55,
        y + 8,
        {
          bold: true,
          size: 16,
          color: COLORS.blue,
          width: 40,
          align: "right",
        }
      );

      y += 53;
    }

    // ------------------------------------
    // TEXT MEASUREMENT
    // ------------------------------------

    function measureText(
      value,
      fontSize,
      width,
      bold = false
    ) {
      doc
        .font(bold ? "Helvetica-Bold" : "Helvetica")
        .fontSize(fontSize);

      return doc.heightOfString(
        String(value ?? ""),
        {
          width,
          lineGap: 2,
        }
      );
    }

    // ------------------------------------
    // INDIVIDUAL FINDING
    // ------------------------------------

    function drawFinding(finding, index) {
      const title =
        `${index + 1}. ${finding.title || "Security finding"}`;

      const severity = String(
        finding.severity || "info"
      ).toLowerCase();

      const severityColors = {
        critical: COLORS.red,
        high: COLORS.orange,
        medium: COLORS.yellow,
        low: COLORS.blue,
        info: COLORS.gray,
      };

      const description =
        `Description: ${finding.description || "No description provided."}`;

      const recommendation =
        `Recommendation: ${finding.recommendation || "Manual review recommended."}`;

      const fileLine =
        `File: ${finding.filePath || "N/A"} | Line: ${finding.line ?? "N/A"}`;

      const scannerLine =
        `Severity: ${severity.toUpperCase()} | Scanner: ${finding.scanner || "N/A"}`;

      const innerWidth = contentWidth - 28;

      const titleHeight =
        measureText(title, 10, innerWidth, true);

      const fileHeight =
        measureText(fileLine, 7, innerWidth);

      const descriptionHeight =
        measureText(description, 8, innerWidth);

      const recommendationHeight =
        measureText(recommendation, 8, innerWidth);

      const cardHeight =
        12 +
        titleHeight +
        7 +
        10 +
        7 +
        fileHeight +
        6 +
        descriptionHeight +
        6 +
        recommendationHeight +
        12;

      // Normal finding card.
      if (cardHeight <= contentBottom - PAGE.top) {
        ensureSpace(cardHeight + 12);

        const cardY = y;

        doc
          .roundedRect(
            PAGE.left,
            cardY,
            contentWidth,
            cardHeight,
            8
          )
          .fill(COLORS.background);

        let detailY = cardY + 12;

        drawText(
          title,
          PAGE.left + 14,
          detailY,
          {
            bold: true,
            size: 10,
            color: COLORS.navy,
            width: innerWidth,
          }
        );

        detailY += titleHeight + 7;

        drawText(
          scannerLine,
          PAGE.left + 14,
          detailY,
          {
            bold: true,
            size: 7,
            color:
              severityColors[severity] || COLORS.gray,
            width: innerWidth,
          }
        );

        detailY += 17;

        drawText(
          fileLine,
          PAGE.left + 14,
          detailY,
          {
            size: 7,
            color: COLORS.muted,
            width: innerWidth,
          }
        );

        detailY += fileHeight + 6;

        drawText(
          description,
          PAGE.left + 14,
          detailY,
          {
            size: 8,
            width: innerWidth,
          }
        );

        detailY += descriptionHeight + 6;

        drawText(
          recommendation,
          PAGE.left + 14,
          detailY,
          {
            size: 8,
            width: innerWidth,
          }
        );

        y = cardY + cardHeight + 12;

        return;
      }

      // Extra-long finding: draw without a fixed-height card.
      ensureSpace(100);

      drawText(title, PAGE.left, y, {
        bold: true,
        size: 10,
        color: COLORS.navy,
        width: contentWidth,
      });

      y += titleHeight + 7;

      drawText(scannerLine, PAGE.left, y, {
        bold: true,
        size: 7,
        color: severityColors[severity] || COLORS.gray,
        width: contentWidth,
      });

      y += 17;

      drawText(fileLine, PAGE.left, y, {
        size: 7,
        color: COLORS.muted,
        width: contentWidth,
      });

      y += fileHeight + 6;

      const blocks = [
        {
          value: description,
          height: descriptionHeight,
        },
        {
          value: recommendation,
          height: recommendationHeight,
        },
      ];

      for (const block of blocks) {
        ensureSpace(block.height + 8);

        drawText(block.value, PAGE.left, y, {
          size: 8,
          width: contentWidth,
        });

        y += block.height + 8;
      }

      y += 8;
    }

    // ------------------------------------
    // FINDINGS SECTION
    // ------------------------------------

    function drawFindings() {
      ensureSpace(35);

      y = sectionTitle("03 Detailed findings", y);

      if (findings.length === 0) {
        const emptyCardHeight = 83;

        ensureSpace(emptyCardHeight + 12);

        doc
          .roundedRect(
            PAGE.left,
            y,
            contentWidth,
            emptyCardHeight,
            9
          )
          .fill("#F0FDF4");

        doc
          .circle(PAGE.left + 28, y + 27, 10)
          .fill(COLORS.green);

        drawText("✓", PAGE.left + 22, y + 20, {
          bold: true,
          size: 12,
          color: COLORS.white,
        });

        drawText(
          "No security findings detected",
          PAGE.left + 48,
          y + 17,
          {
            bold: true,
            size: 12,
            color: COLORS.green,
          }
        );

        drawText(
          "The completed automated scan did not report any findings from the configured scanners.",
          PAGE.left + 48,
          y + 40,
          {
            size: 8,
            color: COLORS.text,
            width: contentWidth - 65,
          }
        );

        y += emptyCardHeight + 18;

        return;
      }

      findings.forEach((finding, index) => {
        drawFinding(finding, index);
      });
    }

    // ------------------------------------
    // DISCLAIMER
    // ------------------------------------

    function drawDisclaimer() {
      const disclaimer =
        "This report reflects the results of automated security tools and is not a guarantee that the application is free from vulnerabilities. Automated scanners may produce false positives or miss issues. Manual security testing is recommended before production deployment.";

      const disclaimerHeight =
        measureText(disclaimer, 7, contentWidth);

      const requiredHeight =
        5 + 1 + 12 + 13 + disclaimerHeight + 8;

      ensureSpace(requiredHeight);

      y += 5;

      doc
        .moveTo(PAGE.left, y)
        .lineTo(PAGE.left + contentWidth, y)
        .strokeColor(COLORS.border)
        .lineWidth(0.7)
        .stroke();

      y += 12;

      drawText(
        "ASSESSMENT DISCLAIMER",
        PAGE.left,
        y,
        {
          bold: true,
          size: 7,
          color: COLORS.muted,
        }
      );

      y += 13;

      drawText(disclaimer, PAGE.left, y, {
        size: 7,
        color: COLORS.muted,
        width: contentWidth,
      });

      y += disclaimerHeight + 8;
    }

    // ------------------------------------
    // FOOTERS AND PAGE NUMBERS
    // ------------------------------------

    function drawFooters() {
      const range = doc.bufferedPageRange();

      for (
        let pageIndex = range.start;
        pageIndex < range.start + range.count;
        pageIndex++
      ) {
        doc.switchToPage(pageIndex);

        const footerY = doc.page.height - 37;

        doc
          .moveTo(PAGE.left, footerY)
          .lineTo(
            doc.page.width - PAGE.right,
            footerY
          )
          .strokeColor(COLORS.border)
          .lineWidth(0.5)
          .stroke();

        drawText(
          "SECURE SCAN • SECURITY ASSESSMENT",
          PAGE.left,
          footerY + 10,
          {
            size: 7,
            color: COLORS.muted,
          }
        );

        drawText(
          `PAGE ${pageIndex - range.start + 1} OF ${range.count}`,
          PAGE.left,
          footerY + 10,
          {
            size: 7,
            color: COLORS.muted,
            width: contentWidth,
            align: "right",
          }
        );
      }

      // Return to the last existing page.
      doc.switchToPage(
        range.start + range.count - 1
      );
    }

    // ------------------------------------
    // GENERATE REPORT
    // ------------------------------------

    drawHeader();

    drawProjectOverview();

    drawSecuritySummary();

    drawFindings();

    drawDisclaimer();

    // Draw footers on existing pages only.
    // This function does not create new pages.
    drawFooters();

    doc.end();

  } catch (error) {
    next(error);
  }
});

export default router;
