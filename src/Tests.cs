using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Drawing;
using System.Threading;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security;

namespace ProjectSafe {
 public static partial class Tests {
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateSymbolicLink(string path,string target,int flags);
  static string root;static int id;
  static string Folder(){var p=Path.Combine(root,(++id).ToString());Directory.CreateDirectory(p);return p;}
  static void Assert(bool value,string message){if(!value)throw new Exception(message);}
  static void Throws(Action fn){try{fn();}catch{return;}throw new Exception("Expected rejection did not occur");}
  static Scan Inspect(string path){return Vault.Inspect(path,CancellationToken.None,null);}
  static string Pack(Scan scan,string dest){return Vault.Pack(scan,dest,CancellationToken.None,null);}
  public static void Demo(string dir){
   Directory.CreateDirectory(dir);Directory.CreateDirectory(Path.Combine(dir,"Медиа"));Directory.CreateDirectory(Path.Combine(dir,"Заметки"));
   using(var image=new Bitmap(640,360))using(var g=Graphics.FromImage(image)){
    g.Clear(Color.FromArgb(23,35,43));using(var brush=new SolidBrush(Color.FromArgb(124,231,192)))g.FillEllipse(brush,232,85,176,176);
    using(var f=new Font("Segoe UI",16,FontStyle.Bold))g.DrawString("ПЕРВЫЙ ПРОЕКТ",f,Brushes.White,215,286);image.Save(Path.Combine(dir,"Медиа","Обложка.png"));
   }
   string shared=Path.Combine(Path.GetDirectoryName(dir),"Пример внешнего звука.wav");
   using(var writer=new BinaryWriter(File.Create(shared))){int len=4410;writer.Write(Encoding.ASCII.GetBytes("RIFF"));writer.Write(36+len);writer.Write(Encoding.ASCII.GetBytes("WAVEfmt "));writer.Write(16);writer.Write((short)1);writer.Write((short)1);writer.Write(22050);writer.Write(22050);writer.Write((short)1);writer.Write((short)8);writer.Write(Encoding.ASCII.GetBytes("data"));writer.Write(len);for(int n=0;n<len;n++)writer.Write((byte)128);}
   string project="<?xml version=\"1.0\"?><mlt><profile frame_rate_num=\"25\" frame_rate_den=\"1\" width=\"640\" height=\"360\"/><producer id=\"cover\"><property name=\"mlt_service\">qimage</property><property name=\"resource\">Медиа/Обложка.png</property></producer><producer id=\"audio\"><property name=\"mlt_service\">avformat</property><property name=\"resource\">../Пример внешнего звука.wav</property></producer><playlist><entry producer=\"cover\" in=\"0\" out=\"49\"/></playlist></mlt>";
   File.WriteAllText(Path.Combine(dir,"Пример.mlt"),project,Encoding.UTF8);
   File.WriteAllText(Path.Combine(dir,"Заметки","Идея.txt"),"Пример проекта. Кадр находится внутри папки, звук — снаружи. Сейф обнаружит его и добавит в копию.\r\nЭто тестовая композиция, созданная для демонстрации проверки путей.",Encoding.UTF8);
  }
  public static void Run(string output) {
   Directory.CreateDirectory(output);root=Path.Combine(output,"fixtures_"+DateTime.Now.ToString("yyyyMMdd_HHmmss")+"_"+Guid.NewGuid().ToString("N").Substring(0,6));Directory.CreateDirectory(root);
   var cases=new List<Tuple<string,Action>>();
   cases.Add(Tuple.Create("Unicode paths, file hashes, empty directory",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"Проект");Directory.CreateDirectory(Path.Combine(src,"Пусто"));File.WriteAllText(Path.Combine(src,"Кадр.txt"),"данные");var original=Vault.Hash(Path.Combine(src,"Кадр.txt"));
    var packed=Pack(Inspect(src),Path.Combine(dir,"Сейф"));Assert(Vault.Verify(packed,CancellationToken.None,null)==1,"count");Assert(Directory.Exists(Path.Combine(packed,"Project","Пусто")),"empty dir");Assert(Vault.Hash(Path.Combine(src,"Кадр.txt"))==original,"original changed");
   }));
   cases.Add(Tuple.Create("Collect external MLT media; keep original project bytes",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"Демо");Demo(src);var hash=Vault.Hash(Path.Combine(src,"Пример.mlt"));var scan=Inspect(src);Assert(scan.Files.Count(x=>x.Linked)==1,"external not collected");Assert(!scan.Findings.Any(x=>x.Level=="Не найден"),"false missing");var packed=Pack(scan,Path.Combine(dir,"Vault"));Assert(Vault.Verify(packed,CancellationToken.None,null)==5,"count");Assert(Vault.Hash(Path.Combine(packed,"Project","Пример.mlt"))==hash,"project changed");
   }));
   cases.Add(Tuple.Create("Missing dependency is reported",(Action)delegate{
    var dir=Folder();File.WriteAllText(Path.Combine(dir,"x.mlt"),"<mlt><producer><property name='resource'>missing.mp4</property></producer></mlt>");Assert(Inspect(dir).Findings.Any(x=>x.Level=="Не найден"),"missing not found");
   }));
   cases.Add(Tuple.Create("Unsupported editor is explicitly reported",(Action)delegate{
    var dir=Folder();File.WriteAllText(Path.Combine(dir,"x.prproj"),"not a parsed project");Assert(Inspect(dir).Findings.Any(x=>x.Level=="Формат"),"coverage warning missing");
   }));
   cases.Add(Tuple.Create("Destination inside source is rejected",(Action)delegate{
    var src=Folder();File.WriteAllText(Path.Combine(src,"a"),"a");Throws(()=>Pack(Inspect(src),Path.Combine(src,"Backup")));
   }));
   cases.Add(Tuple.Create("Source changes after scan are rejected",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);var f=Path.Combine(src,"a");File.WriteAllText(f,"before");var scan=Inspect(src);File.AppendAllText(f,"changed");Throws(()=>Pack(scan,Path.Combine(dir,"save")));Assert(File.ReadAllText(f)=="beforechanged","source touched");
   }));
   cases.Add(Tuple.Create("Corruption of same length is detected",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);File.WriteAllText(Path.Combine(src,"a"),"abc");var packed=Pack(Inspect(src),Path.Combine(dir,"save"));File.WriteAllText(Path.Combine(packed,"Project","a"),"xyz");Throws(()=>Vault.Verify(packed,CancellationToken.None,null));
   }));
   cases.Add(Tuple.Create("Missing file is detected",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);File.WriteAllText(Path.Combine(src,"a"),"abc");var packed=Pack(Inspect(src),Path.Combine(dir,"save"));File.Move(Path.Combine(packed,"Project","a"),Path.Combine(packed,"Project","a.moved"));Throws(()=>Vault.Verify(packed,CancellationToken.None,null));
   }));
   cases.Add(Tuple.Create("Manifest traversal is rejected",(Action)delegate{
    Throws(()=>Vault.SafeChild(root,"../outside"));Throws(()=>Vault.SafeChild(root,"C:\\secret"));Throws(()=>Vault.SafeChild(root,"file:stream"));
   }));
   cases.Add(Tuple.Create("Cancellation leaves an incomplete copy",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);File.WriteAllBytes(Path.Combine(src,"a"),new byte[2*1024*1024]);var token=new CancellationTokenSource();var dest=Path.Combine(dir,"save");Throws(()=>Vault.Pack(Inspect(src),dest,token.Token,p=>token.Cancel()));var bundle=Directory.GetDirectories(dest).Single();var manifest=Vault.Json().Deserialize<Manifest>(File.ReadAllText(Path.Combine(bundle,"manifest.json")));Assert(manifest.Status=="CANCELLED","cancel status");Throws(()=>Vault.Verify(bundle,CancellationToken.None,null));
   }));
   cases.Add(Tuple.Create("New source file during copy is detected",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);File.WriteAllBytes(Path.Combine(src,"a"),new byte[4096]);bool changed=false;Throws(()=>Vault.Pack(Inspect(src),Path.Combine(dir,"save"),CancellationToken.None,p=>{if(!changed){changed=true;File.WriteAllText(Path.Combine(src,"new"),"new file");}}));
   }));
   cases.Add(Tuple.Create("Symlink in source blocks unsafe traversal",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");var target=Path.Combine(dir,"external");Directory.CreateDirectory(src);Directory.CreateDirectory(target);Assert(CreateSymbolicLink(Path.Combine(src,"link"),target,1),"test symlink creation failed");Assert(Inspect(src).Blocked,"link was accepted");
   }));
   cases.Add(Tuple.Create("XML external entities are prohibited",(Action)delegate{
    var src=Folder();File.WriteAllText(Path.Combine(src,"x.mlt"),"<!DOCTYPE mlt [<!ENTITY ext SYSTEM 'file:///C:/Windows/win.ini'>]><mlt>&ext;</mlt>");Assert(Inspect(src).Findings.Any(x=>x.Level=="Формат"&&x.Message.Contains("не проверены")),"unsafe XML accepted");
   }));
   cases.Add(Tuple.Create("Relative MLT opens its assets after relocation with original paths unavailable",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"Исходный проект");Demo(src);var packed=Pack(Inspect(src),Path.Combine(dir,"Сейф"));
    Directory.Move(src,src+"_старый");File.Move(Path.Combine(dir,"Пример внешнего звука.wav"),Path.Combine(dir,"старый звук.wav"));
    string moved=Path.Combine(dir,"Другое место","Перенесённая копия");Directory.CreateDirectory(Path.GetDirectoryName(moved));Directory.Move(packed,moved);
    Assert(Vault.Verify(moved,CancellationToken.None,null)==5,"relocated integrity");var restored=Inspect(Path.Combine(moved,"Ready"));
    Assert(!restored.Findings.Any(x=>x.Level=="Не найден"),"relocated dependency missing");Assert(restored.Files.Count(x=>x.Linked)==2,"not all media relinked");Assert(restored.Files.Where(x=>x.Linked).All(x=>Vault.Inside(x.Source,moved)),"link escaped bundle");
    string xml=File.ReadAllText(Path.Combine(moved,"Ready","Пример.mlt"));Assert(!xml.Contains("root="),"old root remains");Assert(!xml.Contains(src),"old path remains");
   }));
   cases.Add(Tuple.Create("Missing media prevents generating a misleading ready project",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);File.WriteAllText(Path.Combine(src,"x.mlt"),"<mlt><producer><property name='resource'>missing.mp4</property></producer></mlt>");var scan=Inspect(src);Assert(!scan.MltPlans.Single().CanRewrite,"missing marked ready");var packed=Pack(scan,Path.Combine(dir,"save"));Assert(!Directory.Exists(Path.Combine(packed,"Ready")),"unexpected ready copy");Assert(Vault.Verify(packed,CancellationToken.None,null)==1,"original not backed up");
   }));
   cases.Add(Tuple.Create("Absolute XML root and value attributes become relative paths",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");var external=Path.Combine(dir,"Кадры");Directory.CreateDirectory(src);Directory.CreateDirectory(external);File.WriteAllText(Path.Combine(external,"100 процентов.txt"),"frame");
    File.WriteAllText(Path.Combine(src,"x.mlt"),"<mlt root='"+SecurityElement.Escape(external)+"'><producer><property name='resource' value='100 процентов.txt'/></producer></mlt>");var packed=Pack(Inspect(src),Path.Combine(dir,"save"));var result=Inspect(Path.Combine(packed,"Ready"));Assert(!result.Findings.Any(x=>x.Level=="Не найден"),"value resource missing");Assert(File.ReadAllText(Path.Combine(packed,"Ready","x.mlt")).Contains("value=\"../Project/"),"value attribute not rewritten");
   }));
   cases.Add(Tuple.Create("Timewarp keeps speed prefix and links both resource properties",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);File.WriteAllText(Path.Combine(src,"clip.mp4"),"test data");
    File.WriteAllText(Path.Combine(src,"x.mlt"),"<mlt><producer><property name='mlt_service'>timewarp</property><property name='resource'>-0.5:clip.mp4</property><property name='warp_resource'>clip.mp4</property></producer></mlt>");var scan=Inspect(src);Assert(scan.MltPlans.Single().CanRewrite,"timewarp rejected");var packed=Pack(scan,Path.Combine(dir,"save"));string xml=File.ReadAllText(Path.Combine(packed,"Ready","x.mlt"));Assert(xml.Contains("-0.5:../Project/clip.mp4"),"speed changed");Assert(!Inspect(Path.Combine(packed,"Ready")).Findings.Any(x=>x.Level=="Не найден"),"warp source missing");
   }));
   cases.Add(Tuple.Create("Nested project and sequence resources require manual review",(Action)delegate{
    var dir=Folder();File.WriteAllText(Path.Combine(dir,"nested.mlt"),"<mlt/>");File.WriteAllText(Path.Combine(dir,"parent.mlt"),"<mlt><producer><property name='mlt_service'>xml</property><property name='resource'>nested.mlt</property></producer></mlt>");File.WriteAllText(Path.Combine(dir,"sequence.mlt"),"<mlt><producer><property name='resource'>image%04d.png</property></producer></mlt>");var scan=Inspect(dir);Assert(!scan.MltPlans.Single(x=>x.Relative=="parent.mlt").CanRewrite,"nested accepted");Assert(!scan.MltPlans.Single(x=>x.Relative=="sequence.mlt").CanRewrite,"sequence accepted");
   }));
   cases.Add(Tuple.Create("Network references are not opened automatically",(Action)delegate{
    var dir=Folder();File.WriteAllText(Path.Combine(dir,"remote.mlt"),"<mlt><producer><property name='resource'>file://not-a-real-server/share/movie.mp4</property></producer></mlt>");var scan=Inspect(dir);Assert(!scan.MltPlans.Single().CanRewrite,"network marked ready");Assert(scan.Files.Count==1,"network file was added");Assert(scan.Findings.Any(x=>x.Message.Contains("Сетевой ресурс")),"network not reported");
   }));
   cases.Add(Tuple.Create("Kdenlive 1.1 preserves proxy and original references in separate copy",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);var a=Path.Combine(dir,"source.mp4");var p=Path.Combine(dir,"proxy.mp4");File.WriteAllText(a,"source");File.WriteAllText(p,"proxy");
    string xml="<mlt><playlist><property name='kdenlive:docproperties.version'>1.1</property><property name='kdenlive:docproperties.storagefolder'>C:/old/cache</property></playlist><chain><property name='mlt_service'>avformat</property><property name='resource'>"+SecurityElement.Escape(p)+"</property><property name='kdenlive:proxy'>"+SecurityElement.Escape(p)+"</property><property name='kdenlive:originalurl'>"+SecurityElement.Escape(a)+"</property></chain></mlt>";
    File.WriteAllText(Path.Combine(src,"a.kdenlive"),xml);var scan=Inspect(src);Assert(scan.ReadyCount==1,"Kdenlive not ready");Assert(scan.Files.Count(x=>x.Linked)==2,"proxy/source collection");var packed=Pack(scan,Path.Combine(dir,"save"));Assert(File.ReadAllText(Path.Combine(packed,"Project","a.kdenlive"))==xml,"original changed");var restored=Inspect(Path.Combine(packed,"Ready"));Assert(!restored.Findings.Any(x=>x.Level=="Не найден"),"Kdenlive links broken");Assert(!File.ReadAllText(Path.Combine(packed,"Ready","a.kdenlive")).Contains("C:/old/cache"),"old cache leaked");
   }));
   cases.Add(Tuple.Create("Unverified Kdenlive format is not advertised as ready",(Action)delegate{
    var src=Folder();File.WriteAllText(Path.Combine(src,"x.kdenlive"),"<mlt><property name='kdenlive:docproperties.version'>1.04</property></mlt>");Assert(Inspect(src).ReadyCount==0,"old format accepted");
   }));
   cases.Add(Tuple.Create("OpenShot duplicate basenames stay distinct and animation survives",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);Directory.CreateDirectory(Path.Combine(dir,"A"));Directory.CreateDirectory(Path.Combine(dir,"B"));File.WriteAllText(Path.Combine(dir,"A","clip.mp4"),"first");File.WriteAllText(Path.Combine(dir,"B","clip.mp4"),"second");
    string json="{\"version\":{\"openshot-qt\":\"4.1.1\"},\"files\":[{\"path\":\"../A/clip.mp4\"},{\"path\":\"../B/clip.mp4\"}],\"layers\":[],\"clips\":[{\"reader\":{\"path\":\"../A/clip.mp4\"},\"alpha\":{\"Points\":[{\"co\":{\"X\":1,\"Y\":0.25}}]}}]}";
    File.WriteAllText(Path.Combine(src,"native.osp"),json);var scan=Inspect(src);Assert(scan.ReadyCount==1,"OSP not ready");var packed=Pack(scan,Path.Combine(dir,"save"));Assert(Vault.Verify(packed,CancellationToken.None,null)==4,"OSP count");string derived=File.ReadAllText(Path.Combine(packed,"Ready","native.osp"));Assert(derived.Contains("0.25"),"animation lost");var obj=Vault.Json().DeserializeObject(derived) as Dictionary<string,object>;var fs=(object[])obj["files"];string pa=(string)((Dictionary<string,object>)fs[0])["path"],pb=(string)((Dictionary<string,object>)fs[1])["path"];Assert(pa!=pb,"same-name files collided");Assert(File.ReadAllText(Path.Combine(packed,"Ready",pa))=="first","first content wrong");Assert(File.ReadAllText(Path.Combine(packed,"Ready",pb))=="second","second content wrong");
   }));
   cases.Add(Tuple.Create("OpenShot missing thumbnails are optional but missing media is blocking",(Action)delegate{
    var src=Folder();File.WriteAllText(Path.Combine(src,"clip.mp4"),"video");string head="{\"version\":{\"openshot-qt\":\"4.1.1\"},\"files\":[{\"path\":\"clip.mp4\",\"image\":\"@assets/thumbnail/missing.png\"}],\"clips\":[],\"layers\":[]}";File.WriteAllText(Path.Combine(src,"ok.osp"),head);Assert(Inspect(src).OspPlans.Single().CanRewrite,"thumbnail blocks project");File.WriteAllText(Path.Combine(src,"missing.osp"),head.Replace("clip.mp4","absent.mp4"));Assert(!Inspect(src).OspPlans.Single(x=>x.Relative=="missing.osp").CanRewrite,"missing media accepted");
   }));
   cases.Add(Tuple.Create("OpenShot unknown versions and optimized readers require review",(Action)delegate{
    var src=Folder();string data="{\"version\":{\"openshot-qt\":\"3.0.0\"},\"files\":[],\"clips\":[],\"layers\":[]}";File.WriteAllText(Path.Combine(src,"old.osp"),data);File.WriteAllText(Path.Combine(src,"optimized.osp"),data.Replace("3.0.0","4.1.1").Replace("\"files\"","\"auto_optimize\":{\"enabled\":true},\"files\""));Assert(Inspect(src).ReadyCount==0,"unverified OSP accepted");
   }));
   cases.Add(Tuple.Create("Archive rename is detected without touching original",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);File.WriteAllText(Path.Combine(src,"a.mp4"),"source");var packed=Pack(Inspect(src),Path.Combine(dir,"save"));File.Move(Path.Combine(packed,"Project","a.mp4"),Path.Combine(packed,"Project","renamed.mp4"));Throws(()=>Vault.Verify(packed,CancellationToken.None,null));Assert(File.ReadAllText(Path.Combine(src,"a.mp4"))=="source","original changed");
   }));
   cases.Add(Tuple.Create("Locked source fails safely and never gets a complete status",(Action)delegate{
    var dir=Folder();var src=Path.Combine(dir,"src");Directory.CreateDirectory(src);var path=Path.Combine(src,"busy.mp4");File.WriteAllText(path,"locked source");var scan=Inspect(src);var dest=Path.Combine(dir,"save");using(var locked=new FileStream(path,FileMode.Open,FileAccess.ReadWrite,FileShare.None)){Throws(()=>Pack(scan,dest));}var bundle=Directory.GetDirectories(dest).Single();var manifest=Vault.Json().Deserialize<Manifest>(File.ReadAllText(Path.Combine(bundle,"manifest.json")));Assert(manifest.Status=="FAILED","failed copy marked complete");Assert(File.ReadAllText(path)=="locked source","original modified");
   }));
   cases.Add(Tuple.Create("Missing OpenShot LUT is not silently omitted",(Action)delegate{
    var src=Folder();File.WriteAllText(Path.Combine(src,"clip.mp4"),"video");string data="{\"version\":{\"openshot-qt\":\"4.1.1\"},\"files\":[{\"path\":\"clip.mp4\"}],\"clips\":[],\"layers\":[],\"effects\":[{\"lut_path\":\"missing.cube\"}]}";File.WriteAllText(Path.Combine(src,"effect.osp"),data);var scan=Inspect(src);Assert(scan.ReadyCount==0,"missing LUT accepted");Assert(scan.Findings.Any(x=>x.Level=="Не найден"),"missing LUT not reported");
   }));
   cases.Add(Tuple.Create("Kdenlive stale source fingerprint requires native reload before ready",(Action)delegate{
    var src=Folder();File.WriteAllText(Path.Combine(src,"clip.mp4"),"actual media");File.WriteAllText(Path.Combine(src,"stale.kdenlive"),"<mlt><chain id='clip'><property name='resource'>clip.mp4</property><property name='kdenlive:file_size'>1</property></chain><playlist id='main_bin'><property name='kdenlive:docproperties.version'>1.1</property><entry producer='clip'/></playlist></mlt>");var scan=Inspect(src);Assert(scan.ReadyCount==0,"stale metadata accepted");Assert(scan.Findings.Any(x=>x.Message.Contains("Размер исходника отличается")),"stale fingerprint not reported");
   }));
   cases.Add(Tuple.Create("Network XML root is rejected before file probing",(Action)delegate{
    var src=Folder();File.WriteAllText(Path.Combine(src,"network-root.mlt"),"<mlt root='\\\\not-a-real-server\\share'><producer><property name='resource'>clip.mp4</property></producer></mlt>");var scan=Inspect(src);Assert(scan.ReadyCount==0,"network root accepted");Assert(scan.Findings.Any(x=>x.Message.Contains("Сетевые пути")),"network root not rejected");
   }));
   AddPopularTests(cases);
   var results=new List<object>();int failed=0;
   foreach(var test in cases){try{test.Item2();results.Add(new{Name=test.Item1,Passed=true,Error=""});}catch(Exception ex){failed++;results.Add(new{Name=test.Item1,Passed=false,Error=ex.ToString()});}}
   File.WriteAllText(Path.Combine(output,"tests.json"),Vault.Json().Serialize(new{Total=cases.Count,Failed=failed,Fixtures=root,Results=results}),Encoding.UTF8);
   Environment.ExitCode=failed==0?0:1;
  }
 }
}
