import { ShieldCheck } from "lucide-react";

const BrandHeader = () => (
  <header className="brand-header">
    <div className="brand-header-content">
      <ShieldCheck size={28} className="brand-icon" />
      <h1 className="brand-title">SecureScan</h1>
    </div>
  </header>
);

export default BrandHeader;
