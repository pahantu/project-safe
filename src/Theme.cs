using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace ProjectSafe {
 internal static class Surface {
  public static GraphicsPath Round(Rectangle r,int radius) {
   var path=new GraphicsPath();int d=radius*2;
   path.AddArc(r.X,r.Y,d,d,180,90);path.AddArc(r.Right-d,r.Y,d,d,270,90);
   path.AddArc(r.Right-d,r.Bottom-d,d,d,0,90);path.AddArc(r.X,r.Bottom-d,d,d,90,90);path.CloseFigure();return path;
  }
 }
 internal class SoftPanel:Panel {
  public Color Border=Color.FromArgb(40,50,63);
  public SoftPanel(){DoubleBuffered=true;Padding=new Padding(1);}
  protected override void OnPaintBackground(PaintEventArgs e) {
   e.Graphics.Clear(Parent==null?BackColor:Parent.BackColor);e.Graphics.SmoothingMode=SmoothingMode.AntiAlias;
   using(var path=Surface.Round(new Rectangle(0,0,Width-1,Height-1),12))
   using(var fill=new SolidBrush(BackColor))using(var pen=new Pen(Border)){e.Graphics.FillPath(fill,path);e.Graphics.DrawPath(pen,path);}
  }
 }
 internal class SoftButton:Button {
  bool hover;
  public SoftButton(){SetStyle(ControlStyles.UserPaint|ControlStyles.AllPaintingInWmPaint|ControlStyles.OptimizedDoubleBuffer,true);}
  protected override void OnMouseEnter(EventArgs e){hover=true;Invalidate();base.OnMouseEnter(e);}
  protected override void OnMouseLeave(EventArgs e){hover=false;Invalidate();base.OnMouseLeave(e);}
  protected override void OnEnabledChanged(EventArgs e){Invalidate();base.OnEnabledChanged(e);}
  protected override void OnPaint(PaintEventArgs e) {
   var g=e.Graphics;g.SmoothingMode=SmoothingMode.AntiAlias;g.Clear(Parent.BackColor);
   Color fill=Enabled?(hover?ControlPaint.Light(BackColor,.13f):BackColor):Color.FromArgb(29,36,46);
   Color ink=Enabled?ForeColor:Color.FromArgb(123,139,156);
   using(var path=Surface.Round(new Rectangle(0,0,Width-1,Height-1),9))
   using(var brush=new SolidBrush(fill))using(var pen=new Pen(Enabled?FlatAppearance.BorderColor:Color.FromArgb(43,53,65))){g.FillPath(brush,path);g.DrawPath(pen,path);}
   TextRenderer.DrawText(g,Text,Font,ClientRectangle,ink,TextFormatFlags.HorizontalCenter|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
   if(Focused&&ShowFocusCues)ControlPaint.DrawFocusRectangle(g,new Rectangle(5,5,Width-10,Height-10),ink,fill);
  }
 }
 internal class SoftProgress:Control {
  int value,offset;
  ProgressBarStyle style;
  Timer timer=new Timer{Interval=35};
  public SoftProgress(){DoubleBuffered=true;AccessibleRole=AccessibleRole.ProgressBar;AccessibleName="Ход операции";timer.Tick+=delegate{offset=(offset+5)%Math.Max(1,Width);Invalidate();};}
  public int Value{get{return value;}set{this.value=Math.Max(0,Math.Min(100,value));Invalidate();}}
  public ProgressBarStyle Style{get{return style;}set{style=value;timer.Enabled=value==ProgressBarStyle.Marquee;Invalidate();}}
  protected override void OnPaint(PaintEventArgs e){e.Graphics.Clear(Color.FromArgb(37,48,61));using(var brush=new SolidBrush(Color.FromArgb(126,235,197))){if(style==ProgressBarStyle.Marquee)e.Graphics.FillRectangle(brush,offset,0,Math.Max(30,Width/5),Height);else e.Graphics.FillRectangle(brush,0,0,Width*value/100,Height);}}
  protected override void Dispose(bool disposing){if(disposing)timer.Dispose();base.Dispose(disposing);}
 }
}
